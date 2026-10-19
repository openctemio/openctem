// Package refingerprintcmd is the refingerprint command. It re-keys stored findings to the current identity
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
//	refingerprint -dast-repair [-fold-dast-rules r1,r2] [-apply]
//	                                   one-time repair of DAST findings that
//	                                   are one issue under the current recipe
//	                                   (a method the producer stopped sending;
//	                                   the listed fixed-path templates per
//	                                   origin); dry run unless -apply
//	refingerprint -remediation-keys [-tenant <id>] [-apply]
//	                                   re-derive every finding's remediation
//	                                   group key (fix version, secret
//	                                   fingerprint); dry run prints per-kind
//	                                   counts before/after and added, changed,
//	                                   removed; idempotent, one tenant at a time
//	refingerprint -clear-legacy-secret-fingerprints [-before <time>] [-tenant <id>] [-apply]
//	                                   clear the secret fingerprints written
//	                                   before the keyed fingerprint (computed
//	                                   from the tenant id alone, unverifiable);
//	                                   batched, resumable; the next sighting
//	                                   writes the keyed value. Re-derive the
//	                                   remediation keys afterwards
//	refingerprint -correlate [-apply]  one-time cross-rule correlation of
//	                                   existing DAST findings (injection points
//	                                   from stored evidence); dry run reports
//	                                   "would link N" unless -apply
//
// Merges always go through the finding merge (earliest-created survives, the
// other is kept as a tombstone); nothing is deleted.
//
// An applying run writes one tenant audit entry per affected tenant per run (findings.refingerprinted).
//
// Exit status: 0 success, 1 a run failed, 2 usage or connection error.
package refingerprintcmd

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
	"github.com/openctemio/openctem/api/internal/tools/toolaudit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

var _ refingerprint.Store = (*postgres.FindingRekeyRepository)(nil)

// How a report names its run.
const (
	modeDryRun  = "dry run"
	modeApplied = "applied"
)

// Main runs the command with os.Args. It parses its flags on a fresh flag
// set: the server binary that dispatches to it (see cmd/server/tools.go)
// registers its own flags on flag.CommandLine at init.
func Main() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	apply := flag.Bool("apply", false, "commit the re-keys and merges (default is a dry run)")
	tenantFlag := flag.String("tenant", "", "tenant id (default: every tenant with older keys)")
	batch := flag.Int("batch", refingerprint.DefaultBatchSize, "findings per batch")
	maxBatches := flag.Int("max-batches", 0, "stop after this many batches per tenant (0 = until done; an applying run resumes later)")
	asJSON := flag.Bool("json", false, "print reports as JSON")
	timeout := flag.Duration("timeout", 2*time.Hour, "overall time limit")
	dastRepair := flag.Bool("dast-repair", false, "repair forked DAST findings instead of re-keying older versions")
	correlate := flag.Bool("correlate", false, "correlate existing DAST findings across rules (research/134 section 12)")
	remediationKeys := flag.Bool("remediation-keys", false, "re-derive remediation group keys instead of re-keying identities")
	clearLegacy := flag.Bool("clear-legacy-secret-fingerprints", false, "clear the unverifiable secret fingerprints written before the keyed fingerprint (the next sighting rewrites them)")
	before := flag.String("before", "", "with -clear-legacy-secret-fingerprints: clear fingerprints of findings created before this RFC 3339 time (default: when the keyed fingerprint was introduced)")
	foldRules := flag.String("fold-dast-rules", "", "comma-separated DAST rules whose fixed request paths are one issue per origin (with -dast-repair)")
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

	if *clearLegacy {
		os.Exit(runClearLegacySecretFingerprints(ctx, sqlDB, *tenantFlag, *before, *apply, *batch))
	}
	if *remediationKeys {
		os.Exit(runRemediationKeys(ctx, sqlDB, *tenantFlag, *apply, *asJSON, *batch))
	}
	if *correlate {
		os.Exit(runCorrelate(ctx, sqlDB, *tenantFlag, *apply, *asJSON))
	}
	if *dastRepair {
		os.Exit(runDASTRepair(ctx, sqlDB, store, *tenantFlag, vulnerability.ParseFoldRules(*foldRules), *apply, *asJSON))
	}

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
	runID := toolaudit.NewRunID()
	var auditWriter toolaudit.Writer = postgres.NewAuditRepository(&postgres.DB{DB: sqlDB})
	reports := make([]*refingerprint.Report, 0, len(tenants))
	for _, t := range tenants {
		rep, err := svc.Run(ctx, t, refingerprint.Options{Apply: *apply, BatchSize: *batch, MaxBatches: *maxBatches})
		if err != nil {
			fmt.Fprintf(os.Stderr, "refingerprint: tenant %s: %v\n", t, err)
			failed = true
			continue
		}
		reports = append(reports, rep)
		if *apply {
			if err := auditRun(ctx, auditWriter, runID, rep); err != nil {
				fmt.Fprintf(os.Stderr, "refingerprint: tenant %s: %v\n", t, err)
				failed = true
			}
		}
		if !*asJSON {
			mode := modeDryRun
			if rep.Applied {
				mode = modeApplied
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

// auditRun records the tenant's re-keys in its own audit log: one entry per
// tenant per run, only when the run changed something.
func auditRun(ctx context.Context, w toolaudit.Writer, runID string, rep *refingerprint.Report) error {
	if !rep.Applied || (rep.Rekeyed == 0 && rep.Merged == 0) {
		return nil
	}
	tenant, err := shared.IDFromString(rep.TenantID)
	if err != nil {
		return err
	}
	return toolaudit.Record(ctx, w, toolaudit.Event{
		TenantID:     tenant,
		Action:       audit.ActionFindingsRefingerprinted,
		ResourceType: audit.ResourceTypeFinding,
		Actor:        "refingerprint",
		RunID:        runID,
		Counts:       map[string]int{"scanned": rep.Scanned, "rekeyed": rep.Rekeyed, "merged": rep.Merged},
	})
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

// runDASTRepair runs the DAST repair for one tenant or every tenant that has
// DAST findings.
func runDASTRepair(ctx context.Context, db *sql.DB, store *postgres.FindingRekeyRepository, tenantFlag string, fold map[string]bool, apply, asJSON bool) int {
	var tenants []shared.ID
	if tenantFlag != "" {
		id, err := shared.IDFromString(tenantFlag)
		if err != nil {
			fail(2, "-tenant: not an id")
		}
		tenants = []shared.ID{id}
	} else {
		var err error
		if tenants, err = dastTenants(ctx, db); err != nil {
			fail(2, err.Error())
		}
	}
	code := 0
	reports := make([]*postgres.DASTRepairReport, 0, len(tenants))
	for _, t := range tenants {
		rep, err := store.RepairDAST(ctx, t, fold, apply)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dast repair: tenant %s: %v\n", t, err)
			code = 1
			continue
		}
		reports = append(reports, rep)
		if !asJSON {
			mode := modeDryRun
			if rep.Applied {
				mode = modeApplied
			}
			fmt.Printf("tenant %s (%s): scanned %d, merges %d, re-keyed %d\n", rep.TenantID, mode, rep.Scanned, len(rep.Merges), rep.Rekeyed)
			for _, m := range rep.Merges {
				fmt.Printf("  merge %s into %s\n", m.LoserID, m.SurvivorID)
			}
		}
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(reports)
	}
	return code
}

// dastTenants lists the tenants that have live DAST findings.
func dastTenants(ctx context.Context, db *sql.DB) ([]shared.ID, error) {
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT tenant_id FROM findings WHERE identity_key->>'kind' = 'dast' AND status <> 'duplicate'`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if id, err := shared.IDFromString(s); err == nil {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

// runCorrelate backfills cross-rule correlation for one tenant or every
// tenant that has DAST findings.
func runCorrelate(ctx context.Context, db *sql.DB, tenantFlag string, apply, asJSON bool) int {
	var tenants []shared.ID
	if tenantFlag != "" {
		id, err := shared.IDFromString(tenantFlag)
		if err != nil {
			fail(2, "-tenant: not an id")
		}
		tenants = []shared.ID{id}
	} else {
		var err error
		if tenants, err = dastTenants(ctx, db); err != nil {
			fail(2, err.Error())
		}
	}
	repo := postgres.NewFindingCorrelationRepository(&postgres.DB{DB: db})
	code := 0
	reports := make([]*postgres.CorrelationBackfill, 0, len(tenants))
	for _, t := range tenants {
		rep, err := repo.Backfill(ctx, t, apply)
		if err != nil {
			fmt.Fprintf(os.Stderr, "correlate: tenant %s: %v\n", t, err)
			code = 1
			continue
		}
		reports = append(reports, rep)
		if !asJSON {
			mode := modeDryRun
			if rep.Applied {
				mode = modeApplied
			}
			fmt.Printf("tenant %s (%s): injection points %d on %d asset(s); link %d, suggest %d, release %d\n",
				rep.TenantID, mode, rep.Points, rep.Assets, rep.Linked, rep.Suggested, rep.Released)
		}
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(reports)
	}
	return code
}

// runClearLegacySecretFingerprints clears the legacy secret fingerprints.
func runClearLegacySecretFingerprints(ctx context.Context, db *sql.DB, tenantFlag, before string, apply bool, batch int) int {
	cutoff := postgres.LegacySecretFingerprintCutoff
	if before != "" {
		t, err := time.Parse(time.RFC3339, before)
		if err != nil {
			fail(2, "-before: not an RFC 3339 time")
		}
		cutoff = t
	}
	var tenant *shared.ID
	if tenantFlag != "" {
		id, err := shared.IDFromString(tenantFlag)
		if err != nil {
			fail(2, "-tenant: not an id")
		}
		tenant = &id
	}
	rep, err := postgres.ClearLegacySecretFingerprints(ctx, db, tenant, cutoff, apply, batch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "refingerprint: %v\n", err)
		return 1
	}
	if rep.Applied {
		fmt.Printf("cleared %d legacy secret fingerprint(s) (findings created before %s); %d still held by another transaction\n",
			rep.Matched, cutoff.Format(time.RFC3339), rep.Remaining)
	} else {
		fmt.Printf("dry run: %d legacy secret fingerprint(s) would be cleared (findings created before %s)\n", rep.Matched, cutoff.Format(time.RFC3339))
	}
	return 0
}
