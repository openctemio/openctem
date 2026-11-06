package retest_test

// research/62 P0-3 (SW1): every retest is a scan run of kind retest. The run
// is recorded with the retest, linked from it, holds the retest's commands as
// its tasks (so their logs are readable from the run) and settles with the
// verdict. Another tenant cannot list or read it.

import (
	"context"
	"encoding/json"
	"testing"

	scanrunapp "github.com/openctemio/openctem/api/internal/app/scanrun"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

func (fx *fixture) scanRunService() *scanrunapp.Service {
	return scanrunapp.NewService(postgres.NewScanWorkflowRepository(fx.pg), postgres.NewScanWorkflowStepRepository(fx.pg),
		postgres.NewScanRunRepository(fx.pg), postgres.NewStepRunRepository(fx.pg), nil, postgres.NewCommandRepository(fx.pg), nil, logger.NewNop())
}

func TestRetestDB_EveryRetestIsARun(t *testing.T) {
	fx := newFixture(t)
	svc := fx.service()
	runs := fx.scanRunService()
	svc.SetRunRecorder(runs)
	f := fx.newFinding(fx.asset, "confirmed", "exposed-admin-panel")
	rt := fx.request(svc, f)

	if rt.RunID == nil {
		t.Fatal("the retest has no run")
	}
	stored := fx.retest(rt.ID)
	if stored.RunID == nil || *stored.RunID != *rt.RunID {
		t.Fatalf("finding_retests.run_id = %v, want %s", stored.RunID, rt.RunID)
	}

	run, err := runs.GetRunWithStepsForTenant(context.Background(), fx.tenant.String(), rt.RunID.String())
	if err != nil {
		t.Fatal(err)
	}
	if run.Kind != scanrun.RunKindRetest || run.Status != scanrun.RunStatusRunning || !run.ScanWorkflowID.IsZero() {
		t.Fatalf("run kind=%s status=%s workflow=%s, want a running retest run without a workflow", run.Kind, run.Status, run.ScanWorkflowID)
	}
	if run.Subject["finding_id"] != f.String() || run.Subject["retest_id"] != rt.ID.String() {
		t.Fatalf("run subject = %v", run.Subject)
	}
	if len(run.StepRuns) != 1 {
		t.Fatalf("run has %d steps, want 1", len(run.StepRuns))
	}
	step := run.StepRuns[0]

	// Both commands belong to the run: tagged with the run (tasks, logs) and
	// its step, never with a step key (the retest settles the run, not the
	// scan run service).
	rows, err := fx.db.Query(`SELECT payload, scan_run_step_id FROM commands WHERE tenant_id = $1`, fx.tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var raw []byte
		var stepID *string
		if err := rows.Scan(&raw, &stepID); err != nil {
			t.Fatal(err)
		}
		var p map[string]any
		_ = json.Unmarshal(raw, &p)
		if p["scan_run_id"] != rt.RunID.String() || p["step_key"] != nil || stepID == nil || *stepID != step.ID.String() {
			t.Errorf("command not tagged with the run: payload=%v step=%v", p, stepID)
		}
		n++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("%d commands, want 2", n)
	}
	tasks, err := runs.ListRunTasksPage(context.Background(), fx.tenant.String(), rt.RunID.String(), "", 0)
	if err != nil || len(tasks.Items) != 2 {
		t.Fatalf("run tasks = %v, %v; want the 2 commands", tasks, err)
	}

	// The verdict settles the run.
	fx.finishAttempt(rt.CheckCommandID, "detected", "https://shop.example.com/admin", 200)
	fx.finish(rt.ReachCommandID, "detected", "target answered")
	svc.OnCommandFinished(context.Background(), fx.tenant, *rt.ReachCommandID)
	run, err = runs.GetRunWithStepsForTenant(context.Background(), fx.tenant.String(), rt.RunID.String())
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != scanrun.RunStatusCompleted || run.StepRuns[0].Status != scanrun.StepRunStatusCompleted {
		t.Fatalf("after the verdict: run %s, step %s; want completed", run.Status, run.StepRuns[0].Status)
	}

	// Listed under its kind, in its tenant only.
	other := shared.NewID()
	fx.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'retest IT other', $2)`, other.String(), "retest-other-"+other.String())
	t.Cleanup(func() { _, _ = fx.db.Exec(`DELETE FROM tenants WHERE id = $1`, other.String()) })
	list := func(tenant shared.ID) pagination.Result[*scanrun.Run] {
		t.Helper()
		res, err := runs.ListRuns(context.Background(), scanrunapp.ListRunsInput{TenantID: tenant.String(), Kinds: []string{"retest"}, Page: 1, PerPage: 50})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if res := list(fx.tenant); res.Total != 1 || res.Data[0].ID != *rt.RunID {
		t.Fatalf("retest runs of the tenant = %d", res.Total)
	}
	if res := list(other); res.Total != 0 {
		t.Fatalf("another tenant lists %d retest runs, want 0", res.Total)
	}
	if _, err := runs.GetRunWithStepsForTenant(context.Background(), other.String(), rt.RunID.String()); err == nil {
		t.Fatal("another tenant read the retest run")
	}
}
