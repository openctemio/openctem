package compliancechecks

import (
	"context"
	"database/sql"
	"encoding/csv"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func openDB(t *testing.T, readOnly bool) *sql.DB {
	t.Helper()
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	if readOnly {
		url = readOnlyURL(url)
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
	tenant                                    shared.ID
	failNormal, failL2, failJewel, failManual string
	failOverride, pass, naError, na, closed   string
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
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'compliance checks', $2)`, tid, "cc-"+tid)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM audit_logs WHERE tenant_id = $1`, tid)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, tid)
	})
	host, jewel := shared.NewID().String(), shared.NewID().String()
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'h.example.com', 'host')`, host, tid)
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type, is_crown_jewel) VALUES ($1, $2, 'j.example.com', 'host', true)`, jewel, tid)
	ins := func(asset, control, result, status, extra string) string {
		id := shared.NewID().String()
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, priority_class, fingerprint, status,
				finding_type, practice, practice_reason, compliance_framework, compliance_control_id, compliance_result, source_extra)
			VALUES ($1::uuid, $2, $3, 'va', 'nessus', 'm', 'high', 'P2', $1::text, $4, 'compliance', 'compliance', 'compliance',
				'cis', $5, NULLIF($6, ''), $7::jsonb)`, id, tid, asset, status, control, result, extra)
		return id
	}
	l1 := `{"compliance-benchmark-name": "CIS Example Linux", "compliance-benchmark-profile": "Level 1 - Server", "compliance-policy-value": "1"}`
	l2 := `{"compliance-benchmark-name": "CIS Example Linux", "compliance-benchmark-profile": "Level 2 - Server"}`
	f.failNormal = ins(host, "1.1", "fail", "new", l1)
	f.failL2 = ins(host, "1.2", "fail", "confirmed", l2)
	f.failJewel = ins(jewel, "1.1", "fail", "new", l1)
	f.failManual = ins(host, "1.3", "manual", "new", l1)
	f.failOverride = ins(host, "1.4", "fail", "new", l1)
	exec(`UPDATE findings SET severity = 'critical', source_severity = 'high', severity_overridden_at = NOW(),
		severity_override_reason = 'analyst' WHERE id = $1`, f.failOverride)
	f.pass = ins(host, "1.5", "pass", "new", l1)
	f.naError = ins(host, "1.6", "not_applicable", "new",
		`{"compliance-benchmark-name": "CIS Example Linux", "compliance-result": "ERROR", "compliance-error": "audit failed"}`)
	f.na = ins(host, "1.7", "not_applicable", "new", l1)
	f.closed = ins(host, "1.8", "pass", "new", l1)
	exec(`UPDATE findings SET status = 'resolved', closure_reason = 'fixed', verification = 'none', resolved_at = NOW() WHERE id = $1`, f.closed)
	return f
}

func findingState(t *testing.T, db *sql.DB, id string) (status, severity, class, closure string, level sql.NullInt64) {
	t.Helper()
	if err := db.QueryRowContext(context.Background(), `SELECT status, severity, COALESCE(priority_class, ''),
			COALESCE(closure_reason, ''), compliance_level FROM findings WHERE id = $1`, id).
		Scan(&status, &severity, &class, &closure, &level); err != nil {
		t.Fatal(err)
	}
	return
}

func TestRun_DryRunThenApply_DB(t *testing.T) {
	rw := openDB(t, false)
	f := seed(t, rw)
	ctx := context.Background()

	// Dry run on a read-only connection: aggregates, no change.
	ro := openDB(t, true)
	rep, err := Run(ctx, ro, Options{Tenant: &f.tenant, BatchSize: 3})
	if err != nil {
		t.Fatal(err)
	}
	tr := rep.Tenants[0]
	if tr.Open != 8 || tr.Closed != 1 {
		t.Fatalf("open %d closed %d", tr.Open, tr.Closed)
	}
	if tr.ByResult["fail"] != 4 || tr.ByResult["manual"] != 1 || tr.ByResult["pass"] != 1 || tr.ByResult["error"] != 1 ||
		tr.ByResult["not_applicable"] != 1 {
		t.Fatalf("by result = %v", tr.ByResult)
	}
	if tr.ToClose["pass"] != 1 || tr.ToClose["error"] != 1 || tr.ToClose["not_applicable"] != 1 {
		t.Fatalf("to close = %v", tr.ToClose)
	}
	// Normal L1: high>medium; L2: high>low; jewel L1: high stays; manual:
	// high>low; override kept.
	if tr.SeverityMoves["high>medium"] != 1 || tr.SeverityMoves["high>low"] != 2 || tr.KeptOverride != 1 {
		t.Fatalf("severity moves = %v kept %d", tr.SeverityMoves, tr.KeptOverride)
	}
	if tr.Controls != 8 || len(tr.Benchmarks) != 1 || tr.Benchmarks[0].Key != "cis-example-linux" {
		t.Fatalf("controls %d benchmarks %+v", tr.Controls, tr.Benchmarks)
	}
	if s, sev, _, _, _ := findingState(t, rw, f.failNormal); s != "new" || sev != "high" {
		t.Fatalf("dry run changed a finding: %s %s", s, sev)
	}
	var states int
	if err := rw.QueryRowContext(ctx, `SELECT count(*) FROM compliance_check_states WHERE tenant_id = $1`, f.tenant.String()).Scan(&states); err != nil || states != 0 {
		t.Fatalf("dry run recorded %d states (%v)", states, err)
	}

	// Apply needs an undo file.
	if _, err := Run(ctx, rw, Options{Tenant: &f.tenant, Apply: true}); err == nil {
		t.Fatal("apply without an undo file ran")
	}
	undo := filepath.Join(t.TempDir(), "undo.csv")
	rep, err = Run(ctx, rw, Options{Tenant: &f.tenant, Apply: true, UndoPath: undo, BatchSize: 3})
	if err != nil {
		t.Fatal(err)
	}
	tr = rep.Tenants[0]
	if tr.ClosedApplied != 3 || tr.StatesRecorded != 8 {
		t.Fatalf("applied = %+v", tr)
	}
	want := map[string][3]string{ // status, severity, class
		f.failNormal: {"new", "medium", "P3"}, f.failL2: {"confirmed", "low", "P3"}, f.failJewel: {"new", "high", "P2"},
		f.failManual: {"new", "low", "P3"}, f.failOverride: {"new", "critical", "P2"},
	}
	for id, w := range want {
		s, sev, c, _, _ := findingState(t, rw, id)
		if s != w[0] || sev != w[1] || c != w[2] {
			t.Errorf("finding %s = %s %s %s, want %v", id, s, sev, c, w)
		}
	}
	if _, _, _, _, lvl := findingState(t, rw, f.failL2); !lvl.Valid || lvl.Int64 != 2 {
		t.Errorf("level 2 not set: %v", lvl)
	}
	for _, id := range []string{f.pass, f.naError, f.na} {
		if s, _, _, closure, _ := findingState(t, rw, id); s != "resolved" || closure != "reclassified_check_state" {
			t.Errorf("finding %s = %s (%s), want resolved as reclassified_check_state", id, s, closure)
		}
	}
	if s, _, _, closure, _ := findingState(t, rw, f.closed); s != "resolved" || closure != "fixed" {
		t.Errorf("a closed finding was touched: %s %s", s, closure)
	}
	var result string
	if err := rw.QueryRowContext(ctx, `SELECT result FROM compliance_check_states WHERE tenant_id = $1 AND control_id = '1.6'`,
		f.tenant.String()).Scan(&result); err != nil || result != "error" {
		t.Fatalf("errored check state = %q (%v), want error", result, err)
	}
	// The audit log records every close and the run.
	var audits, runs, timeline int
	_ = rw.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding.status_changed'
		AND metadata->>'closure_reason' = 'reclassified_check_state'`, f.tenant.String()).Scan(&audits)
	_ = rw.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'findings.reclassified'
		AND metadata->>'command' = 'compliance-checks'`, f.tenant.String()).Scan(&runs)
	_ = rw.QueryRowContext(ctx, `SELECT count(*) FROM finding_activities WHERE tenant_id = $1 AND activity_type = 'status_changed'
		AND changes->>'reason' = 'reclassified_check_state'`, f.tenant.String()).Scan(&timeline)
	if audits != 3 || runs != 1 || timeline != 3 {
		t.Fatalf("audit closes %d, run entries %d, timeline %d; want 3, 1, 3", audits, runs, timeline)
	}
	// The undo file holds every changed row's previous values.
	fh, err := os.Open(undo)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(fh).ReadAll()
	_ = fh.Close()
	if err != nil || len(recs) != 1+3+5 { // header, 3 closes, 5 re-classified (each gets its level; the override keeps its severity)
		t.Fatalf("undo rows = %d (%v)", len(recs), err)
	}

	// A rerun changes nothing; the undo file is never overwritten.
	if _, err := Run(ctx, rw, Options{Tenant: &f.tenant, Apply: true, UndoPath: undo}); err == nil {
		t.Fatal("an existing undo file was reused")
	}
	rep, err = Run(ctx, rw, Options{Tenant: &f.tenant, Apply: true, UndoPath: filepath.Join(t.TempDir(), "u2.csv")})
	if err != nil {
		t.Fatal(err)
	}
	if tr = rep.Tenants[0]; tr.Applied != 0 || tr.StatesRecorded != 0 {
		t.Fatalf("rerun changed %d findings, %d states", tr.Applied, tr.StatesRecorded)
	}
}

// A run limited to one tenant never reads or writes another tenant's
// findings.
func TestRun_TenantIsolation_DB(t *testing.T) {
	rw := openDB(t, false)
	a, b := seed(t, rw), seed(t, rw)
	rep, err := Run(context.Background(), rw, Options{Tenant: &a.tenant, Apply: true, UndoPath: filepath.Join(t.TempDir(), "u.csv")})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Tenants) != 1 || rep.Tenants[0].TenantID != a.tenant.String() {
		t.Fatalf("tenants = %+v", rep.Tenants)
	}
	if s, sev, _, _, _ := findingState(t, rw, b.failNormal); s != "new" || sev != "high" {
		t.Fatalf("tenant B's finding changed: %s %s", s, sev)
	}
	if s, _, _, _, _ := findingState(t, rw, b.pass); s != "new" {
		t.Fatalf("tenant B's pass was closed: %s", s)
	}
	var n int
	if err := rw.QueryRowContext(context.Background(), `SELECT count(*) FROM compliance_check_states WHERE tenant_id = $1`,
		b.tenant.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("tenant B states = %d (%v)", n, err)
	}
}
