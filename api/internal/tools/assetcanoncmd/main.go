// Package assetcanoncmd is the asset-canonical command: it moves stored asset
// names to the CTIS 2.0 canonical form (internal/app/assetcanon). The server
// runs the same migration on start; the command is for a dry run before an
// upgrade, for one tenant, and for undoing the renames before a downgrade.
//
//	DATABASE_URL  postgres connection string; when unset it is built from the
//	              server's DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME and
//	              DB_SSLMODE, so it runs as-is inside the API container
//
// Usage:
//
//	asset-canonical                 dry run for every tenant: counts what
//	                                would change; the connection is
//	                                read-only (safe on a live database)
//	asset-canonical -tenant <id>    one tenant
//	asset-canonical -apply          rename and merge; idempotent (a canonical
//	                                name is not changed again), one
//	                                transaction per asset
//	asset-canonical -revert         give renamed assets their old names back
//	                                (merges are not undone)
//	asset-canonical -json           print the reports as JSON
//
// The output is aggregate counts only, no names. An applying run writes one
// tenant audit entry per affected tenant (assets.merged).
//
// Exit status: 0 success, 1 a tenant failed, 2 usage or connection error.
package assetcanoncmd

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

	"github.com/openctemio/openctem/api/internal/app/assetcanon"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/tools/toolaudit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Main runs the command with os.Args on a fresh flag set (the server binary
// that dispatches to it registers its own flags at init).
func Main() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	apply := flag.Bool("apply", false, "rename and merge (default is a dry run)")
	revert := flag.Bool("revert", false, "give renamed assets their old names back")
	tenantFlag := flag.String("tenant", "", "tenant id (default: every tenant)")
	asJSON := flag.Bool("json", false, "print reports as JSON")
	timeout := flag.Duration("timeout", 2*time.Hour, "overall time limit")
	flag.Parse()
	if *apply && *revert {
		fail(2, "-apply and -revert exclude each other")
	}

	dbURL := databaseURL()
	if dbURL == "" {
		fail(2, "DATABASE_URL (or DB_HOST/DB_*) must be set in the environment")
	}
	if !*apply && !*revert {
		dbURL = readOnlyURL(dbURL) // a dry run only reads; the server enforces it
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
	db := &postgres.DB{DB: sqlDB}
	store := postgres.NewAssetCanonicalRepository(db)
	var tenants []shared.ID
	if *tenantFlag != "" {
		id, err := shared.IDFromString(*tenantFlag)
		if err != nil {
			fail(2, "-tenant: not an id")
		}
		tenants = []shared.ID{id}
	} else if tenants, err = store.Tenants(ctx); err != nil {
		fail(2, err.Error())
	}
	svc := assetcanon.NewService(store)
	if *revert {
		os.Exit(runRevert(ctx, svc, tenants))
	}
	os.Exit(run(ctx, svc, postgres.NewAuditRepository(db), tenants, *apply, *asJSON))
}

// AuditRun records an applied run that changed a tenant's assets in the
// tenant's audit log: one entry per tenant per run, counts only.
func AuditRun(ctx context.Context, w toolaudit.Writer, runID, actor string, rep assetcanon.Report) error {
	if !rep.Changed() {
		return nil
	}
	tid, err := shared.IDFromString(rep.TenantID)
	if err != nil {
		return err
	}
	return toolaudit.Record(ctx, w, toolaudit.Event{
		TenantID: tid, Action: audit.ActionAssetsMerged, ResourceType: audit.ResourceTypeAsset,
		Actor: actor, RunID: runID,
		Counts: map[string]int{"renamed": rep.Renamed, "assets_merged": rep.Merged, "conflicts": rep.Conflicts},
	})
}

func run(ctx context.Context, svc *assetcanon.Service, w toolaudit.Writer, tenants []shared.ID, apply, asJSON bool) int {
	status := 0
	runID := toolaudit.NewRunID()
	total := assetcanon.Report{}
	var reports []assetcanon.Report
	for _, t := range tenants {
		rep, err := svc.Run(ctx, t, apply)
		if err != nil {
			fmt.Fprintf(os.Stderr, "asset-canonical: tenant %s: %v\n", t, err)
			status = 1
			continue
		}
		if apply {
			if err := AuditRun(ctx, w, runID, "asset-canonical", rep); err != nil {
				fmt.Fprintf(os.Stderr, "asset-canonical: tenant %s: audit: %v\n", t, err)
				status = 1
			}
		}
		total.Scanned += rep.Scanned
		total.Unchanged += rep.Unchanged
		total.Renamed += rep.Renamed
		total.Merged += rep.Merged
		total.Conflicts += rep.Conflicts
		total.Raced += rep.Raced
		if rep.Changed() || rep.Conflicts > 0 {
			reports = append(reports, rep)
		}
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"applied": apply, "total": total, "tenants": reports})
		return status
	}
	mode := "dry run"
	if apply {
		mode = "applied"
	}
	fmt.Printf("asset-canonical (%s): %d tenants, %d assets checked; %d renamed, %d merged, %d left (another type holds the name), %d changed meanwhile\n",
		mode, len(tenants), total.Scanned, total.Renamed, total.Merged, total.Conflicts, total.Raced)
	return status
}

func runRevert(ctx context.Context, svc *assetcanon.Service, tenants []shared.ID) int {
	status, reverted, kept := 0, 0, 0
	for _, t := range tenants {
		r, k, err := svc.Revert(ctx, t)
		if err != nil {
			fmt.Fprintf(os.Stderr, "asset-canonical: tenant %s: %v\n", t, err)
			status = 1
		}
		reverted += r
		kept += k
	}
	fmt.Printf("asset-canonical (revert): %d tenants; %d renames undone, %d kept (the asset changed or the old name is taken)\n",
		len(tenants), reverted, kept)
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
	fmt.Fprintln(os.Stderr, "asset-canonical: "+msg)
	os.Exit(code)
}
