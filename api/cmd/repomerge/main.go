// Command repomerge merges a tenant's duplicate repository assets: one
// repository that is two assets because repository import named it
// "org/repo" and CI "github.com/org/repo", or because a rename or transfer
// made CI create a new asset while the old one kept the findings, branches,
// gate policy and coverage expectation. Each group is merged into its oldest
// asset by the asset merge (every reference moves; findings are re-keyed and
// folded; nothing is deleted but the emptied duplicate assets). See
// internal/infra/postgres/repository_merge.go.
//
//	DATABASE_URL  postgres connection string; when unset it is built from the
//	              server's DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME and
//	              DB_SSLMODE, so it runs as-is inside the API container
//
// Usage:
//
//	repomerge                 dry run for every tenant: counts what would be
//	                          merged; the connection is read-only, so it
//	                          changes nothing (safe on a live database)
//	repomerge -tenant <id>    one tenant
//	repomerge -apply          merge; idempotent (a merged repository is one
//	                          asset and is not found again), one transaction
//	                          per repository
//	repomerge -json           print the reports as JSON (with the asset ids)
//	repomerge -apply -resolve also merge a repository whose duplicates carry
//	                          several gate policies, keeping the one at least
//	                          as strict as every other (never merged when
//	                          none is; refused without -resolve)
//
// The default output is aggregate counts only, no names.
//
// Exit status: 0 success, 1 a merge failed, 2 usage or connection error.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func main() {
	apply := flag.Bool("apply", false, "merge (default is a dry run)")
	tenantFlag := flag.String("tenant", "", "tenant id (default: every tenant with repository assets)")
	asJSON := flag.Bool("json", false, "print reports as JSON")
	resolve := flag.Bool("resolve", false, "merge a repository whose duplicates carry several gate policies, keeping the strictest")
	timeout := flag.Duration("timeout", time.Hour, "overall time limit")
	flag.Parse()

	dbURL := databaseURL()
	if dbURL == "" {
		fail(2, "DATABASE_URL (or DB_HOST/DB_*) must be set in the environment")
	}
	if !*apply {
		// A dry run only reads; the server enforces it.
		dbURL = readOnlyURL(dbURL)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	sqlDB, err := sql.Open("postgres", dbURL)
	if err != nil {
		fail(2, "open database: "+err.Error())
	}
	defer func() { _ = sqlDB.Close() }()
	if err := sqlDB.PingContext(ctx); err != nil {
		fail(2, "connect: "+err.Error())
	}
	repo := postgres.NewRepositoryMergeRepository(&postgres.DB{DB: sqlDB})

	var tenants []shared.ID
	if *tenantFlag != "" {
		id, err := shared.IDFromString(*tenantFlag)
		if err != nil {
			fail(2, "-tenant: not an id")
		}
		tenants = []shared.ID{id}
	} else if tenants, err = repo.TenantsWithRepositories(ctx); err != nil {
		fail(2, err.Error())
	}
	os.Exit(run(ctx, repo, tenants, *apply, *resolve, *asJSON))
}

// run merges (or counts) per tenant and prints the reports; it returns the
// exit status.
func run(ctx context.Context, repo *postgres.RepositoryMergeRepository, tenants []shared.ID, apply, resolve, asJSON bool) int {
	status := 0
	total := postgres.RepositoryMergeReport{Applied: apply}
	reports := make([]*postgres.RepositoryMergeReport, 0, len(tenants))
	affected := 0
	for _, t := range tenants {
		rep, err := repo.MergeDuplicateRepositories(ctx, t, apply, resolve)
		if err != nil {
			fmt.Fprintf(os.Stderr, "repomerge: tenant %s: %v\n", t, err)
			status = 1
			continue
		}
		if rep.FailedGroups > 0 {
			status = 1
			for _, f := range rep.FailureDetail {
				fmt.Fprintf(os.Stderr, "repomerge: tenant %s: %s\n", t, f)
			}
		}
		if rep.Groups > 0 || rep.FailedGroups > 0 || rep.RefusedGroups > 0 {
			affected++
			reports = append(reports, rep)
		}
		total.Groups += rep.Groups
		total.AssetsMerged += rep.AssetsMerged
		total.Findings += rep.Findings
		total.Branches += rep.Branches
		total.Pipelines += rep.Pipelines
		total.Runs += rep.Runs
		total.GatePolicies += rep.GatePolicies
		total.Expectations += rep.Expectations
		total.FailedGroups += rep.FailedGroups
		total.RefusedGroups += rep.RefusedGroups
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"total": total, "tenants": reports})
		return status
	}
	mode := "dry run"
	if apply {
		mode = "applied"
	}
	fmt.Printf("repomerge (%s): %d tenants checked, %d with duplicates; %d repositories, %d duplicate assets merged into them; "+
		"moved: %d findings, %d branches, %d pipelines, %d runs, %d gate policies, %d coverage expectations; %d failed; %d refused (several gate policies: -resolve keeps the strictest)\n",
		mode, len(tenants), affected, total.Groups, total.AssetsMerged, total.Findings, total.Branches, total.Pipelines,
		total.Runs, total.GatePolicies, total.Expectations, total.FailedGroups, total.RefusedGroups)
	return status
}

func databaseURL() string {
	if v := os.Getenv("DATABASE_URL"); v != "" {
		return v
	}
	host := os.Getenv("DB_HOST")
	if host == "" {
		return ""
	}
	get := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(get("DB_USER", "openctem"), os.Getenv("DB_PASSWORD")),
		Host:     host + ":" + get("DB_PORT", "5432"),
		Path:     "/" + get("DB_NAME", "openctem"),
		RawQuery: "sslmode=" + url.QueryEscape(get("DB_SSLMODE", "disable")),
	}
	return u.String()
}

func readOnlyURL(dsn string) string {
	if u, err := url.Parse(dsn); err == nil && (u.Scheme == "postgres" || u.Scheme == "postgresql") {
		q := u.Query()
		q.Set("default_transaction_read_only", "on")
		u.RawQuery = q.Encode()
		return u.String()
	}
	return dsn + " default_transaction_read_only=on"
}

func fail(code int, msg string) {
	fmt.Fprintln(os.Stderr, "repomerge: "+msg)
	os.Exit(code)
}
