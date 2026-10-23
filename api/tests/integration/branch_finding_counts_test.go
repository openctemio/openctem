package integration

// Branch finding counters (repository_branches.findings_*), kept by statement
// triggers since migration branch_finding_counts_per_statement. The counters
// must equal a recount of the branch's open findings after every kind of
// write (multi-row insert, status, severity and branch moves, no-op updates,
// deletes), exactly as the row trigger they replace kept them. The migration
// test runs the same writes under the old row triggers (down) and the new
// statement triggers (up) and compares both with the recount.

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type branchCounts struct{ total, critical, high, medium, low int }

// branchCountsStored reads the counters of a branch.
func branchCountsStored(ctx context.Context, t *testing.T, q queryer, branchID string) branchCounts {
	t.Helper()
	var c branchCounts
	if err := q.QueryRowContext(ctx, `SELECT findings_total, findings_critical, findings_high, findings_medium, findings_low
		FROM repository_branches WHERE id = $1`, branchID).Scan(&c.total, &c.critical, &c.high, &c.medium, &c.low); err != nil {
		t.Fatalf("read branch counters: %v", err)
	}
	return c
}

// branchCountsRecount is the definition the counters must match: the open
// findings of the branch, in total and per severity.
func branchCountsRecount(ctx context.Context, t *testing.T, q queryer, branchID string) branchCounts {
	t.Helper()
	var c branchCounts
	if err := q.QueryRowContext(ctx, `SELECT
			count(*) FILTER (WHERE is_open_finding_status(status)),
			count(*) FILTER (WHERE severity = 'critical' AND is_open_finding_status(status)),
			count(*) FILTER (WHERE severity = 'high' AND is_open_finding_status(status)),
			count(*) FILTER (WHERE severity = 'medium' AND is_open_finding_status(status)),
			count(*) FILTER (WHERE severity = 'low' AND is_open_finding_status(status))
		FROM findings WHERE branch_id = $1`, branchID).Scan(&c.total, &c.critical, &c.high, &c.medium, &c.low); err != nil {
		t.Fatalf("recount branch: %v", err)
	}
	return c
}

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// exerciseBranchCounts seeds a tenant with one repository and two branches,
// runs a fixed sequence of multi-row writes and checks the counters of both
// branches against the recount after each step. It returns the counters
// after every step, so two trigger implementations can be compared.
func exerciseBranchCounts(ctx context.Context, t *testing.T, q queryer) []branchCounts {
	t.Helper()
	tenant := shared.NewID().String()
	mustExecQ(ctx, t, q, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tenant, "bc-"+tenant)
	var asset, branchA, branchB string
	if err := q.QueryRowContext(ctx, `INSERT INTO assets (tenant_id, name, asset_type) VALUES ($1, $2, 'repository') RETURNING id`,
		tenant, "github.com/acme/bc-"+tenant).Scan(&asset); err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	mustExecQ(ctx, t, q, `INSERT INTO asset_repositories (asset_id) VALUES ($1)`, asset)
	for name, dst := range map[string]*string{"main": &branchA, "dev": &branchB} {
		if err := q.QueryRowContext(ctx, `INSERT INTO repository_branches (repository_id, name) VALUES ($1, $2) RETURNING id`,
			asset, name).Scan(dst); err != nil {
			t.Fatalf("insert branch: %v", err)
		}
	}

	var out []branchCounts
	check := func(step string) {
		t.Helper()
		for _, b := range []string{branchA, branchB} {
			got, want := branchCountsStored(ctx, t, q, b), branchCountsRecount(ctx, t, q, b)
			if got != want {
				t.Fatalf("after %s: branch %s counters %+v, recount %+v", step, b, got, want)
			}
			out = append(out, got)
		}
	}

	// One multi-row insert across both branches and no branch, all
	// severities, open and new statuses.
	sevs := []string{"critical", "high", "medium", "low", "info"}
	stats := []string{"new", "confirmed", "in_progress", "fix_applied"}
	var rows []string
	for i := 0; i < 60; i++ {
		branch := "NULL"
		switch i % 3 {
		case 0:
			branch = "'" + branchA + "'"
		case 1:
			branch = "'" + branchB + "'"
		}
		rows = append(rows, fmt.Sprintf("('%s','%s',%s,'sast','semgrep','m','%s','%s','bc-%s-%d')",
			tenant, asset, branch, sevs[i%len(sevs)], stats[i%len(stats)], tenant[:8], i))
	}
	mustExecQ(ctx, t, q, `INSERT INTO findings (tenant_id, asset_id, branch_id, source, tool_name, message, severity, status, fingerprint) VALUES `+
		strings.Join(rows, ","))
	check("multi-row insert")

	// Close a third of them in one statement.
	mustExecQ(ctx, t, q, `UPDATE findings SET status = 'resolved', resolution = 'auto_fixed', closure_reason = 'fixed',
		verification = 'covered_scan', resolved_at = now() WHERE tenant_id = $1 AND fingerprint ~ '-[0-9]*[05]$'`, tenant)
	check("close")

	// Re-rate severities.
	mustExecQ(ctx, t, q, `UPDATE findings SET severity = CASE severity WHEN 'low' THEN 'critical' WHEN 'high' THEN 'medium' ELSE severity END
		WHERE tenant_id = $1`, tenant)
	check("severity change")

	// Move findings between branches, and one off its branch.
	mustExecQ(ctx, t, q, `UPDATE findings SET branch_id = CASE WHEN branch_id = $2 THEN $3::uuid ELSE $2::uuid END
		WHERE tenant_id = $1 AND branch_id IS NOT NULL AND fingerprint ~ '-[0-9]*[147]$'`, tenant, branchA, branchB)
	mustExecQ(ctx, t, q, `UPDATE findings SET branch_id = NULL WHERE tenant_id = $1 AND fingerprint = $2`, tenant, "bc-"+tenant[:8]+"-3")
	check("branch move")

	// The ingest upsert: INSERT ... ON CONFLICT DO UPDATE fires the update
	// trigger for the rows that conflicted (here: re-rated and reopened)
	// and the insert trigger for the new row.
	mustExecQ(ctx, t, q, `INSERT INTO findings (tenant_id, asset_id, branch_id, source, tool_name, message, severity, status, fingerprint)
		SELECT $1::uuid, $2::uuid, $3::uuid, 'sast', 'semgrep', 'm', 'critical', 'new', 'bc-' || left($1::text, 8) || '-' || g
		FROM unnest(ARRAY['0', '5', '6', 'upsert']) g
		ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET severity = EXCLUDED.severity, status = EXCLUDED.status,
			resolution = NULL, closure_reason = NULL, verification = NULL, resolved_at = NULL`, tenant, asset, branchB)
	check("upsert")

	// A re-sighting writes no counted input.
	mustExecQ(ctx, t, q, `UPDATE findings SET last_seen_at = now(), severity = severity WHERE tenant_id = $1`, tenant)
	check("no-op update")

	// Reopen some.
	mustExecQ(ctx, t, q, `UPDATE findings SET status = 'confirmed', resolution = NULL, closure_reason = NULL, verification = NULL, resolved_at = NULL
		WHERE tenant_id = $1 AND status = 'resolved' AND fingerprint ~ '-[0-9]*0$'`, tenant)
	check("reopen")

	mustExecQ(ctx, t, q, `DELETE FROM findings WHERE tenant_id = $1 AND fingerprint ~ '-[0-9]*[29]$'`, tenant)
	check("delete")
	return out
}

func mustExecQ(ctx context.Context, t *testing.T, q queryer, query string, args ...any) {
	t.Helper()
	if _, err := q.ExecContext(ctx, query, args...); err != nil {
		t.Fatalf("%.80s: %v", query, err)
	}
}

func TestBranchFindingCounts_MatchRecount(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	exerciseBranchCounts(ctx, t, tx)
}

// TestBranchFindingCounts_OneRecountPerStatement: a multi-row insert of N
// findings on one branch updates the branch row once, not N times (the row
// trigger recounted the whole branch for every row: quadratic in the report
// size, and one hot row lock held across the upload).
func TestBranchFindingCounts_OneRecountPerStatement(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()

	tenant := shared.NewID().String()
	mustExecQ(ctx, t, tx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tenant, "bc1-"+tenant)
	var asset, branch string
	if err := tx.QueryRowContext(ctx, `INSERT INTO assets (tenant_id, name, asset_type) VALUES ($1, $2, 'repository') RETURNING id`,
		tenant, "github.com/acme/bc1-"+tenant).Scan(&asset); err != nil {
		t.Fatal(err)
	}
	mustExecQ(ctx, t, tx, `INSERT INTO asset_repositories (asset_id) VALUES ($1)`, asset)
	if err := tx.QueryRowContext(ctx, `INSERT INTO repository_branches (repository_id, name) VALUES ($1, 'main') RETURNING id`,
		asset).Scan(&branch); err != nil {
		t.Fatal(err)
	}
	branchUpdates := func() int {
		t.Helper()
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(sum(n_tup_upd), 0) FROM pg_stat_xact_user_tables
			WHERE relname = 'repository_branches'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := branchUpdates()
	const n = 200
	mustExecQ(ctx, t, tx, `INSERT INTO findings (tenant_id, asset_id, branch_id, source, tool_name, message, severity, fingerprint)
		SELECT $1::uuid, $2::uuid, $3::uuid, 'sast', 'semgrep', 'm', 'high', 'bc1-' || $1::text || '-' || g FROM generate_series(1, $4::int) g`,
		tenant, asset, branch, n)
	if got := branchUpdates() - before; got != 1 {
		t.Errorf("a %d-row insert updated the branch row %d times, want 1", n, got)
	}
	if got := branchCountsStored(ctx, t, tx, branch); got.total != n || got.high != n {
		t.Errorf("counters after the insert: %+v, want total and high %d", got, n)
	}
}

// TestMigrationBranchCountsPerStatement runs the down and up migration in a
// rolled-back transaction as the schema owner, with the same writes under
// the row triggers and the statement triggers: both keep counters equal to
// the recount, step by step.
func TestMigrationBranchCountsPerStatement(t *testing.T) {
	if testdb.MigratorURL() == "" {
		t.Skip("DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", testdb.MigratorURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("database not available: %v", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()

	const dir = "../../migrations"
	version := testdb.MigrationVersion(t, dir, "branch_finding_counts_per_statement")
	apply := func(direction string) {
		t.Helper()
		path := filepath.Join(dir, fmt.Sprintf("%06d_branch_finding_counts_per_statement.%s.sql", version, direction))
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			t.Fatalf("%s: %v", filepath.Base(path), err)
		}
	}
	triggers := func() string {
		t.Helper()
		var names string
		if err := tx.QueryRowContext(ctx, `SELECT string_agg(tgname, ',' ORDER BY tgname) FROM pg_trigger
			WHERE tgrelid = 'findings'::regclass AND tgname LIKE '%branch%count%'`).Scan(&names); err != nil {
			t.Fatal(err)
		}
		return names
	}

	apply("down")
	if got := triggers(); got != "trg_update_branch_finding_counts_delete,trg_update_branch_finding_counts_insert,trg_update_branch_finding_counts_update" {
		t.Fatalf("after down: triggers %q", got)
	}
	rowTrigger := exerciseBranchCounts(ctx, t, tx)

	apply("up")
	if got := triggers(); got != "trg_findings_branch_counts_delete,trg_findings_branch_counts_insert,trg_findings_branch_counts_update" {
		t.Fatalf("after up: triggers %q", got)
	}
	statementTrigger := exerciseBranchCounts(ctx, t, tx)

	if fmt.Sprint(rowTrigger) != fmt.Sprint(statementTrigger) {
		t.Errorf("counters differ between the row and statement triggers:\nrow       %v\nstatement %v", rowTrigger, statementTrigger)
	}
}

// TestBranchFindingCounts_ConcurrentWriters: concurrent committed writers
// (inserts, ingest upserts, status, severity and branch moves, deletes), each
// statement spanning both branches, leave the counters equal to the recount,
// and none of them fails: the statement trigger locks the branch rows in one
// order, after the read committed snapshot of the last writer to commit.
func TestBranchFindingCounts_ConcurrentWriters(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	tenant := shared.NewID().String()
	mustExecQ(ctx, t, db, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tenant, "bcc-"+tenant)
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenant) })
	var asset, branchA, branchB string
	if err := db.QueryRowContext(ctx, `INSERT INTO assets (tenant_id, name, asset_type) VALUES ($1, $2, 'repository') RETURNING id`,
		tenant, "github.com/acme/bcc-"+tenant).Scan(&asset); err != nil {
		t.Fatal(err)
	}
	mustExecQ(ctx, t, db, `INSERT INTO asset_repositories (asset_id) VALUES ($1)`, asset)
	for name, dst := range map[string]*string{"main": &branchA, "dev": &branchB} {
		if err := db.QueryRowContext(ctx, `INSERT INTO repository_branches (repository_id, name) VALUES ($1, $2) RETURNING id`,
			asset, name).Scan(dst); err != nil {
			t.Fatal(err)
		}
	}

	const writers, rounds = 8, 15
	var wg sync.WaitGroup
	errs := make(chan error, writers*rounds*6)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			// Each writer owns its findings (so row locks on findings never
			// collide) but every statement touches both shared branches.
			fp := fmt.Sprintf("bcc-%s-%d-", tenant[:8], w)
			stmts := []struct {
				q    string
				args []any
			}{
				{`INSERT INTO findings (tenant_id, asset_id, branch_id, source, tool_name, message, severity, status, fingerprint)
					SELECT $1::uuid, $2::uuid, CASE WHEN g % 2 = 0 THEN $3::uuid ELSE $4::uuid END, 'sast', 'semgrep', 'm',
						(ARRAY['critical','high','medium','low','info'])[1 + g % 5], 'new', $5 || g
					FROM generate_series(1, 10) g
					ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET status = 'confirmed', severity = 'high'`,
					[]any{tenant, asset, branchA, branchB, fp}},
				{`UPDATE findings SET status = 'resolved', resolution = 'auto_fixed', closure_reason = 'fixed',
					verification = 'covered_scan', resolved_at = now() WHERE tenant_id = $1 AND fingerprint LIKE $2 || '%' AND fingerprint ~ '[13579]$'`,
					[]any{tenant, fp}},
				{`UPDATE findings SET branch_id = CASE WHEN branch_id = $3 THEN $4::uuid ELSE $3::uuid END, severity = 'critical'
					WHERE tenant_id = $1 AND fingerprint LIKE $2 || '%' AND branch_id IS NOT NULL`,
					[]any{tenant, fp, branchA, branchB}},
				{`DELETE FROM findings WHERE tenant_id = $1 AND fingerprint LIKE $2 || '%' AND fingerprint ~ '[48]$'`,
					[]any{tenant, fp}},
			}
			for r := 0; r < rounds; r++ {
				for _, s := range stmts {
					if _, err := db.ExecContext(ctx, s.q, s.args...); err != nil {
						errs <- fmt.Errorf("writer %d round %d: %w", w, r, err)
						return
					}
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	for _, b := range []string{branchA, branchB} {
		if got, want := branchCountsStored(ctx, t, db, b), branchCountsRecount(ctx, t, db, b); got != want {
			t.Errorf("branch %s counters %+v, recount %+v", b, got, want)
		}
	}
}
