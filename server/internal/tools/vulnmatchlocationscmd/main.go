// Package vulnmatchlocationscmd is the vulnmatch-locations command
// (docs/architecture/vulnerability-matching.md, "Locations"): it folds the
// version-match findings stored once per service of a host before locations
// existed into one finding per host, product, version and CVE, and reverts
// that fold.
//
//	vulnmatch-locations -tenant <id>[,<id>...] | -all-tenants [-apply] [-json]
//	vulnmatch-locations -down -tenant <id> | -all-tenants [-run <run id>] [-apply] [-json]
//
// Without -apply it only reports, on a read-only connection. Every fold and
// every revert is audited per finding and summarized per tenant.
package vulnmatchlocationscmd

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/internal/tools/toolaudit"
	"github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

const actor = "vulnmatch-locations"

// Main runs the command.
func Main() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	apply := flag.Bool("apply", false, "write the changes (default is a dry run)")
	down := flag.Bool("down", false, "revert the journaled folds instead of folding")
	tenantFlag := flag.String("tenant", "", "tenant id, or a comma-separated list")
	allTenants := flag.Bool("all-tenants", false, "every tenant with version-match findings on services (or, with -down, with folds to revert)")
	runID := flag.String("run", "", "with -down: revert only this run (default: every fold not reverted yet)")
	asJSON := flag.Bool("json", false, "print reports as JSON")
	timeout := flag.Duration("timeout", time.Hour, "overall time limit")
	flag.Parse()

	if (*tenantFlag == "") == !*allTenants {
		fail(2, "pass -tenant <id>[,<id>...] or -all-tenants")
	}
	if *runID != "" {
		if _, err := shared.IDFromString(*runID); err != nil || !*down {
			fail(2, "-run takes a run id and needs -down")
		}
	}
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		fail(2, "DATABASE_URL must be set in the environment")
	}
	if !*apply {
		// A dry run only reads; the server enforces it.
		dbURL = readOnlyURL(dbURL)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fail(2, "open database")
	}
	defer func() { _ = db.Close() }()
	if err := db.PingContext(ctx); err != nil {
		fail(2, "connect: "+err.Error())
	}
	repo := postgres.NewLocationMergeRepository(&postgres.DB{DB: db})
	tenants, err := tenantsOf(ctx, repo, *tenantFlag, *down)
	if err != nil {
		fail(2, err.Error())
	}
	os.Exit(Run(ctx, repo, postgres.NewAuditRepository(&postgres.DB{DB: db}), tenants, *down, *apply, *runID, *asJSON))
}

// Run folds (or, with down, reverts) the tenants one by one and returns the
// exit code. Each tenant's applied run is summarized in its audit log.
func Run(ctx context.Context, repo *postgres.LocationMergeRepository, w toolaudit.Writer, tenants []shared.ID,
	down, apply bool, revertRun string, asJSON bool,
) int {
	run := toolaudit.NewRunID()
	code := 0
	var reports []any
	for _, t := range tenants {
		if down {
			rep, err := repo.RevertLocationMerges(ctx, t, revertRun, apply)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: tenant %s: %v\n", actor, t, err)
				code = 1
				continue
			}
			reports = append(reports, rep)
			if apply && rep.Reverted > 0 {
				code = record(ctx, w, t, run, map[string]int{"reverted": rep.Reverted, "skipped": rep.Skipped}, code)
			}
			if !asJSON {
				fmt.Printf("tenant %s (%s): revert %d, skipped %d\n", t, mode(apply), rep.Reverted, rep.Skipped)
				for _, e := range rep.Entries {
					if e.Skipped != "" {
						fmt.Printf("  %s into %s: skipped (%s)\n", e.LoserID, e.SurvivorID, e.Skipped)
					} else if len(e.Kept) > 0 {
						fmt.Printf("  %s into %s: survivor columns changed since, kept: %s\n", e.LoserID, e.SurvivorID, strings.Join(e.Kept, ", "))
					}
				}
			}
			continue
		}
		rep, err := repo.PlanLocationMerges(ctx, t, apply, run)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: tenant %s: %v\n", actor, t, err)
			code = 1
			continue
		}
		reports = append(reports, rep)
		if apply && rep.Merged > 0 {
			code = record(ctx, w, t, run, map[string]int{"merged": rep.Merged, "groups_skipped": rep.Skipped, "scanned": rep.Scanned}, code)
		}
		if !asJSON {
			fmt.Printf("tenant %s (%s): findings %d, groups %d, findings folded %d, groups skipped %d\n",
				t, mode(apply), rep.Scanned, len(rep.Groups), rep.Merged, rep.Skipped)
			for _, g := range rep.Groups {
				state := "fold"
				if g.Skipped != "" {
					state = "skip (" + g.Skipped + ")"
				}
				fmt.Printf("  %s %s [%s]:", state, g.Survivor.FindingID, g.Survivor.Service)
				for _, l := range g.Losers {
					fmt.Printf(" %s [%s, %s -> %s]", l.FindingID, l.Service, l.Status, l.Location)
				}
				fmt.Println()
				for _, n := range g.Notes {
					fmt.Println("    note: " + n)
				}
			}
		}
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"run_id": run, "applied": apply, "down": down, "tenants": reports})
	} else if apply {
		fmt.Println("run " + run)
	}
	return code
}

func record(ctx context.Context, w toolaudit.Writer, t shared.ID, run string, counts map[string]int, code int) int {
	if err := toolaudit.Record(ctx, w, toolaudit.Event{TenantID: t, Action: audit.ActionFindingLocationChanged,
		ResourceType: audit.ResourceTypeFinding, Actor: actor, RunID: run, Counts: counts}); err != nil {
		fmt.Fprintf(os.Stderr, "%s: tenant %s: audit: %v\n", actor, t, err)
		return 1
	}
	return code
}

func tenantsOf(ctx context.Context, repo *postgres.LocationMergeRepository, flagValue string, down bool) ([]shared.ID, error) {
	if flagValue == "" {
		return repo.LocationMergeTenants(ctx, down)
	}
	var out []shared.ID
	for _, s := range strings.Split(flagValue, ",") {
		id, err := shared.IDFromString(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("-tenant: %q is not an id", s)
		}
		out = append(out, id)
	}
	return out, nil
}

func mode(apply bool) string {
	if apply {
		return "applied"
	}
	return "dry run"
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
	fmt.Fprintln(os.Stderr, actor+": "+msg)
	os.Exit(code)
}
