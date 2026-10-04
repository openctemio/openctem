// Command refingerprint re-keys stored findings to the current identity
// recipe (RFC-043 §6). See internal/app/refingerprint.
//
//	DATABASE_URL  postgres connection string; when unset it is built from the
//	              server's DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME and
//	              DB_SSLMODE, so it runs as-is inside the API container
//
// Usage:
//
//	refingerprint                      dry run for every tenant with older keys:
//	                                   reports re-keys, would-merge pairs and
//	                                   findings that cannot be recomputed; the
//	                                   connection is read-only, so it changes
//	                                   nothing (safe on a live database)
//	refingerprint -tenant <id>         one tenant
//	refingerprint -apply               commit; resumable (re-run continues from
//	                                   the checkpoint), idempotent; scan
//	                                   auto-resolve is paused per tenant while
//	                                   its run is open
//	refingerprint -json                print the reports as JSON
//
// Merges always go through the finding merge (earliest-created survives, the
// other is kept as a tombstone); nothing is deleted.
//
// Exit status: 0 success, 1 a run failed, 2 usage or connection error.
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

	"github.com/openctemio/openctem/api/internal/app/refingerprint"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

var _ refingerprint.Store = (*postgres.FindingRekeyRepository)(nil)

func main() {
	apply := flag.Bool("apply", false, "commit the re-keys and merges (default is a dry run)")
	tenantFlag := flag.String("tenant", "", "tenant id (default: every tenant with older keys)")
	batch := flag.Int("batch", refingerprint.DefaultBatchSize, "findings per batch")
	maxBatches := flag.Int("max-batches", 0, "stop after this many batches per tenant (0 = until done; an applying run resumes later)")
	asJSON := flag.Bool("json", false, "print reports as JSON")
	timeout := flag.Duration("timeout", 2*time.Hour, "overall time limit")
	flag.Parse()

	if *batch <= 0 || *batch > 10000 {
		fail(2, "-batch must be between 1 and 10000")
	}
	dbURL := databaseURL()
	if dbURL == "" {
		fail(2, "DATABASE_URL (or DB_HOST/DB_*) must be set in the environment")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if !*apply {
		// A dry run only reads; the server enforces it.
		dbURL = readOnlyURL(dbURL)
	}
	sqlDB, err := sql.Open("postgres", dbURL)
	if err != nil {
		fail(2, "open database: "+err.Error())
	}
	defer func() { _ = sqlDB.Close() }()
	if err := sqlDB.PingContext(ctx); err != nil {
		fail(2, "connect: "+err.Error())
	}
	store := postgres.NewFindingRekeyRepository(&postgres.DB{DB: sqlDB})
	svc := refingerprint.NewService(store)

	var tenants []shared.ID
	if *tenantFlag != "" {
		id, err := shared.IDFromString(*tenantFlag)
		if err != nil {
			fail(2, "-tenant: not an id")
		}
		tenants = []shared.ID{id}
	} else if tenants, err = store.TenantsBelowVersion(ctx, vulnerability.IdentityVersion); err != nil {
		fail(2, err.Error())
	}

	failed := false
	reports := make([]*refingerprint.Report, 0, len(tenants))
	for _, t := range tenants {
		rep, err := svc.Run(ctx, t, refingerprint.Options{Apply: *apply, BatchSize: *batch, MaxBatches: *maxBatches})
		if err != nil {
			fmt.Fprintf(os.Stderr, "refingerprint: tenant %s: %v\n", t, err)
			failed = true
			continue
		}
		reports = append(reports, rep)
		if !*asJSON {
			mode := "dry run"
			if rep.Applied {
				mode = "applied"
			}
			fmt.Printf("tenant %s (%s): scanned %d, re-keyed %d, merged %d, kept %d %v, completed %v, resumed %v\n",
				rep.TenantID, mode, rep.Scanned, rep.Rekeyed, rep.Merged, rep.SkippedTotal(), rep.Skipped, rep.Completed, rep.Resumed)
			for _, m := range rep.Merges {
				fmt.Printf("  merge %s into %s\n", m.LoserID, m.SurvivorID)
			}
		}
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(reports)
	}
	if failed {
		os.Exit(1)
	}
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

// readOnlyURL makes every transaction of the connection read-only
// (default_transaction_read_only), for a URL or a key=value DSN.
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
	fmt.Fprintln(os.Stderr, "refingerprint: "+msg)
	os.Exit(code)
}
