package findingpractice

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		testdb.Skipf(t, "cannot reach DATABASE_URL: %v", err)
	}
	return db
}

type fixture struct {
	tenant                      shared.ID
	cisOpen, cisClosed, vaOpen  string
	derivedOpen, derivedChanged string
}

func seed(t *testing.T, db *sql.DB) fixture {
	t.Helper()
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	f := fixture{tenant: shared.NewID()}
	tid := f.tenant.String()
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'practice backfill', $2)`, tid, "fp-"+tid)
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, tid) })
	host, repo := shared.NewID().String(), shared.NewID().String()
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'h.example.com', 'host'), ($3, $2, 'r.example.com', 'repository')`, host, tid, repo)
	ins := func(asset, source, ftype, status string, practice, reason any) string {
		id := shared.NewID().String()
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, finding_type, practice, practice_reason)
			VALUES ($1::uuid, $2, $3, $4, 'tool', 'm', 'high', $1::text, $5, $6, $7, $8)`, id, tid, asset, source, status, ftype, practice, reason)
		return id
	}
	f.cisOpen = ins(host, "va", "compliance", "new", "other", nil)
	f.cisClosed = ins(host, "va", "compliance", "resolved", "other", nil)
	f.vaOpen = ins(host, "va", "vulnerability", "confirmed", "other", nil)
	f.derivedOpen = ins(repo, "sast", "vulnerability", "new", "aspm", "code_and_pipeline")
	// Derived before, but stale (a closed one is never re-derived).
	f.derivedChanged = ins(host, "va", "vulnerability", "resolved", "aspm", "code_and_pipeline")
	return f
}

func practiceOf(t *testing.T, db *sql.DB, id string) (string, sql.NullString) {
	t.Helper()
	var p string
	var r sql.NullString
	if err := db.QueryRowContext(context.Background(), `SELECT practice, practice_reason FROM findings WHERE id = $1`, id).Scan(&p, &r); err != nil {
		t.Fatal(err)
	}
	return p, r
}

func TestRun_DryRunChangesNothing_ApplyIsRerunnable_DB(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	f := seed(t, db)

	rep, err := Run(ctx, db, Options{Tenant: &f.tenant, BatchSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	tr := rep.Tenants[0]
	if rep.Apply || tr.Findings != 5 || tr.Scanned != 4 || tr.Changed != 3 {
		t.Fatalf("dry run report = %+v", tr)
	}
	if tr.Before["other"] != 3 || tr.Before["aspm"] != 2 || tr.After["compliance"] != 2 || tr.After["infra"] != 1 || tr.After["aspm"] != 2 || tr.After["other"] != 0 {
		t.Fatalf("before %v after %v", tr.Before, tr.After)
	}
	if tr.Moves["other>compliance"].Open != 1 || tr.Moves["other>compliance"].Closed != 1 || tr.Moves["other>infra"].Open != 1 {
		t.Fatalf("moves = %+v", tr.Moves)
	}
	if p, r := practiceOf(t, db, f.cisOpen); p != "other" || r.Valid {
		t.Fatalf("dry run wrote %s %v", p, r)
	}

	rep, err = Run(ctx, db, Options{Tenant: &f.tenant, Apply: true, BatchSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Tenants[0].Applied != 3 {
		t.Fatalf("applied = %d", rep.Tenants[0].Applied)
	}
	for id, want := range map[string]string{f.cisOpen: "compliance", f.cisClosed: "compliance", f.vaOpen: "infra", f.derivedOpen: "aspm", f.derivedChanged: "aspm"} {
		if p, _ := practiceOf(t, db, id); p != want {
			t.Fatalf("%s = %s, want %s", id, p, want)
		}
	}
	// The assets whose findings moved are marked for the dashboard facts.
	var dirty int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM dash_dirty_assets WHERE tenant_id = $1`, f.tenant.String()).Scan(&dirty); err != nil {
		t.Fatal(err)
	}
	if dirty == 0 {
		t.Fatal("no dashboard fact refresh queued for the moved findings")
	}

	// Rerun: nothing left to change.
	rep, err = Run(ctx, db, Options{Tenant: &f.tenant, Apply: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Tenants[0].Changed != 0 || rep.Tenants[0].Applied != 0 {
		t.Fatalf("rerun changed %d", rep.Tenants[0].Changed)
	}
}

// One tenant's run never reads or writes another tenant's findings.
func TestRun_TenantIsolation_DB(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	a, b := seed(t, db), seed(t, db)
	if _, err := Run(ctx, db, Options{Tenant: &a.tenant, Apply: true}); err != nil {
		t.Fatal(err)
	}
	if p, r := practiceOf(t, db, b.cisOpen); p != "other" || r.Valid {
		t.Fatalf("tenant B changed by tenant A's run: %s %v", p, r)
	}
}

// The compliance SLA re-baseline: a dry run reports aggregates only; -apply
// moves an open compliance finding's deadline to its compliance window from
// first detection (never earlier), records the timeline entry and the undo
// file, and a rerun changes nothing. Vulnerabilities and closed findings are
// never touched.
func TestRun_ComplianceSLARebaseline_DB(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	f := seed(t, db)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// Detected 20 days ago, P2: the vulnerability window (15 days) made it
	// overdue; the compliance window (90 days) does not.
	for _, id := range []string{f.cisOpen, f.cisClosed, f.vaOpen} {
		exec(`UPDATE findings SET priority_class = 'P2', first_detected_at = now() - interval '20 days',
			sla_deadline = now() - interval '5 days' WHERE id = $1`, id)
	}

	rep, err := Run(ctx, db, Options{Tenant: &f.tenant, SLA: true})
	if err != nil {
		t.Fatal(err)
	}
	s := rep.Tenants[0].SLA
	if s == nil || s.Considered != 1 || s.Extended != 1 || s.OverdueBefore != 1 || s.OverdueAfter != 0 || s.ExtensionDays != 75 {
		t.Fatalf("dry run SLA = %+v", s)
	}
	var overdue string
	if err := db.QueryRowContext(ctx, `SELECT sla_status FROM findings WHERE id = $1`, f.cisOpen).Scan(&overdue); err != nil {
		t.Fatal(err)
	}

	if _, err := Run(ctx, db, Options{Tenant: &f.tenant, SLA: true, Apply: true}); err == nil {
		t.Fatal("-sla -apply without an undo file must be refused")
	}
	undo := t.TempDir() + "/undo.csv"
	rep, err = Run(ctx, db, Options{Tenant: &f.tenant, SLA: true, Apply: true, UndoPath: undo})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Tenants[0].SLA.Applied != 1 {
		t.Fatalf("applied = %+v", rep.Tenants[0].SLA)
	}
	var days int
	var status string
	if err := db.QueryRowContext(ctx, `SELECT round(extract(epoch FROM sla_deadline - first_detected_at) / 86400)::int, sla_status FROM findings WHERE id = $1`, f.cisOpen).Scan(&days, &status); err != nil {
		t.Fatal(err)
	}
	if days != 90 || status == overdue {
		t.Fatalf("compliance deadline = first detection + %d days, status %s (was %s)", days, status, overdue)
	}
	for _, id := range []string{f.cisClosed, f.vaOpen} {
		var d int
		if err := db.QueryRowContext(ctx, `SELECT round(extract(epoch FROM sla_deadline - first_detected_at) / 86400)::int FROM findings WHERE id = $1`, id).Scan(&d); err != nil {
			t.Fatal(err)
		}
		if d != 15 {
			t.Fatalf("%s moved to %d days: only open compliance findings move", id, d)
		}
	}
	var entries int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM finding_activities WHERE finding_id = $1 AND activity_type = 'sla_rebaselined'`, f.cisOpen).Scan(&entries); err != nil {
		t.Fatal(err)
	}
	if entries != 1 {
		t.Fatalf("timeline entries = %d", entries)
	}
	raw, err := os.ReadFile(undo) //nolint:gosec // test temp file
	if err != nil || !strings.Contains(string(raw), f.cisOpen) {
		t.Fatalf("undo file = %q, %v", raw, err)
	}

	rep, err = Run(ctx, db, Options{Tenant: &f.tenant, SLA: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Tenants[0].SLA.Extended != 0 {
		t.Fatalf("rerun would extend %d", rep.Tenants[0].SLA.Extended)
	}
}
