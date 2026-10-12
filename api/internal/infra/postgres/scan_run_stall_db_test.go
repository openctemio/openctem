package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type stallFixture struct {
	tenant, workflow, run, stepA, stepB shared.ID
}

// seedStall: a running run started 10 minutes ago; step a completed 10
// minutes ago, step b (chained on a) still pending.
func seedStall(ctx context.Context, t *testing.T, db *sql.DB) stallFixture {
	t.Helper()
	f := stallFixture{tenant: seedScanTriggerTenant(ctx, t, db), workflow: shared.NewID(), run: shared.NewID(),
		stepA: shared.NewID(), stepB: shared.NewID()}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO scan_workflows (id, tenant_id, name) VALUES ($1, $2, 'stall')`, []any{f.workflow.String(), f.tenant.String()}},
		{`INSERT INTO scan_runs (id, tenant_id, scan_workflow_id, trigger_type, status, started_at, created_at)
		  VALUES ($1, $2, $3, 'manual', 'running', now() - interval '10 minutes', now() - interval '10 minutes')`,
			[]any{f.run.String(), f.tenant.String(), f.workflow.String()}},
		{`INSERT INTO scan_run_steps (id, scan_run_id, step_key, step_order, status, created_at, completed_at)
		  VALUES ($1, $2, 'a', 1, 'completed', now() - interval '10 minutes', now() - interval '10 minutes')`,
			[]any{f.stepA.String(), f.run.String()}},
		{`INSERT INTO scan_run_steps (id, scan_run_id, step_key, step_order, status, created_at)
		  VALUES ($1, $2, 'b', 2, 'pending', now() - interval '10 minutes')`,
			[]any{f.stepB.String(), f.run.String()}},
	} {
		if _, err := db.ExecContext(ctx, q.sql, q.args...); err != nil {
			t.Fatalf("%v\n%s", err, q.sql)
		}
	}
	return f
}

func stalledIDs(ctx context.Context, t *testing.T, repo *ScanRunRepository) map[shared.ID]shared.ID {
	t.Helper()
	got, err := repo.StalledRuns(ctx, time.Now().Add(-2*time.Minute), 1000)
	if err != nil {
		t.Fatal(err)
	}
	out := map[shared.ID]shared.ID{}
	for _, s := range got {
		out[s.RunID] = s.TenantID
	}
	return out
}

// research/62 SG-10: a run whose pending step waits on nothing is found,
// with its own tenant; one with a report still ingesting, a step in flight
// or a recent step change is not.
func TestStalledRuns(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanRunRepository(&DB{DB: db})
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}

	f := seedStall(ctx, t, db)
	if got := stalledIDs(ctx, t, repo); got[f.run] != f.tenant {
		t.Fatalf("stalled run not found with its tenant: %v", got)
	}

	// a's report is still being ingested: b is waiting for it, not stalled.
	sensor := seedJobSensor(ctx, t, db, f.tenant)
	cmd := shared.NewID()
	exec(`INSERT INTO commands (id, tenant_id, type, status, scan_run_step_id) VALUES ($1, $2, 'scan', 'completed', $3)`,
		cmd.String(), f.tenant.String(), f.stepA.String())
	report := shared.NewID()
	exec(`INSERT INTO ingest_reports (id, tenant_id, sensor_id, report_id, command_id, state, media_type, header_digest, expires_at)
	      VALUES ($1, $2, $3, $4, $5, 'processing', 'application/x', 'd', now() + interval '1 hour')`,
		report.String(), f.tenant.String(), sensor.String(), shared.NewID().String(), cmd.String())
	if got := stalledIDs(ctx, t, repo); got[f.run] != (shared.ID{}) {
		t.Fatal("a run waiting for an ingest was reported stalled")
	}
	// The report failed: nothing will call back, so the run is stalled.
	exec(`UPDATE ingest_reports SET state = 'failed' WHERE id = $1`, report.String())
	if got := stalledIDs(ctx, t, repo); got[f.run] != f.tenant {
		t.Fatal("a run whose report failed is not reported stalled")
	}

	// A step in flight, or a step that changed a moment ago: not stalled.
	f2 := seedStall(ctx, t, db)
	exec(`UPDATE scan_run_steps SET status = 'queued' WHERE id = $1`, f2.stepA.String())
	f3 := seedStall(ctx, t, db)
	exec(`UPDATE scan_run_steps SET completed_at = now() WHERE id = $1`, f3.stepA.String())
	got := stalledIDs(ctx, t, repo)
	if _, ok := got[f2.run]; ok {
		t.Error("a run with a queued step was reported stalled")
	}
	if _, ok := got[f3.run]; ok {
		t.Error("a run whose step just completed was reported stalled")
	}
}

// A plan saved for a pending step that never got its commands (a crash
// between the two) is released after a while, with its targets; a plan whose
// step has commands, or a fresh one, is kept.
func TestReleaseOrphanStagePlans(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanRunRepository(&DB{DB: db})
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	plan := func(f stallFixture, key string, age string) {
		exec(`INSERT INTO scan_run_stage_plans (tenant_id, run_id, stage_key, planned_at) VALUES ($1, $2, $3, now() - $4::interval)`,
			f.tenant.String(), f.run.String(), key, age)
		exec(`INSERT INTO scan_run_targets (tenant_id, run_id, stage_key, target_key, origin, decision) VALUES ($1, $2, $3, 'example.com', 'seed', 'planned')`,
			f.tenant.String(), f.run.String(), key)
	}
	count := func(f stallFixture) (plans, targets int) {
		t.Helper()
		_ = db.QueryRowContext(ctx, `SELECT count(*) FROM scan_run_stage_plans WHERE run_id = $1 AND stage_key = 'b'`, f.run.String()).Scan(&plans)
		_ = db.QueryRowContext(ctx, `SELECT count(*) FROM scan_run_targets WHERE run_id = $1 AND stage_key = 'b'`, f.run.String()).Scan(&targets)
		return
	}

	orphan, fresh, withCmd := seedStall(ctx, t, db), seedStall(ctx, t, db), seedStall(ctx, t, db)
	plan(orphan, "b", "10 minutes")
	plan(fresh, "b", "10 seconds")
	plan(withCmd, "b", "10 minutes")
	exec(`INSERT INTO commands (id, tenant_id, type, status, scan_run_step_id) VALUES ($1, $2, 'scan', 'pending', $3)`,
		shared.NewID().String(), withCmd.tenant.String(), withCmd.stepB.String())

	if _, err := repo.ReleaseOrphanStagePlans(ctx, time.Now().Add(-2*time.Minute), 1000); err != nil {
		t.Fatal(err)
	}
	if p, tg := count(orphan); p != 0 || tg != 0 {
		t.Errorf("orphan plan kept: %d plans, %d targets", p, tg)
	}
	if p, tg := count(fresh); p != 1 || tg != 1 {
		t.Errorf("fresh plan released: %d plans, %d targets", p, tg)
	}
	if p, tg := count(withCmd); p != 1 || tg != 1 {
		t.Errorf("plan with a command released: %d plans, %d targets", p, tg)
	}
}
