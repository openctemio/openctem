package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/workflow"
)

// Canceling an automation run (RFC-046 §8): its open steps end, and neither
// the run nor a finished step is rewritten afterwards by an executor that
// was still working on it. Only the run's own tenant closes its steps.

type wfCancelFixture struct {
	ctx    context.Context
	db     *sql.DB
	runs   *WorkflowRunRepository
	nodes  *WorkflowNodeRunRepository
	tenant shared.ID
}

func newWFCancelFixture(t *testing.T) *wfCancelFixture {
	t.Helper()
	ctx := context.Background()
	db := openScanDB(t)
	return &wfCancelFixture{ctx: ctx, db: db, tenant: seedScanTriggerTenant(ctx, t, db),
		runs: NewWorkflowRunRepository(&DB{DB: db}), nodes: NewWorkflowNodeRunRepository(&DB{DB: db})}
}

func (f *wfCancelFixture) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := f.db.ExecContext(f.ctx, q, args...); err != nil {
		t.Fatalf("fixture: %v\n%s", err, q)
	}
}

// run seeds a running workflow run of tenant with one node run per status.
func (f *wfCancelFixture) run(t *testing.T, tenant shared.ID, statuses ...string) (shared.ID, []shared.ID) {
	t.Helper()
	wf, run := shared.NewID(), shared.NewID()
	f.exec(t, `INSERT INTO workflows (id, tenant_id, name) VALUES ($1, $2, 'cancel probe')`, wf.String(), tenant.String())
	f.exec(t, `INSERT INTO workflow_runs (id, workflow_id, tenant_id, trigger_type, status, started_at)
		VALUES ($1, $2, $3, 'manual', 'running', NOW())`, run.String(), wf.String(), tenant.String())
	var ids []shared.ID
	for i, st := range statuses {
		node, nr := shared.NewID(), shared.NewID()
		key := "n" + string(rune('a'+i))
		f.exec(t, `INSERT INTO workflow_nodes (id, workflow_id, node_key, node_type, name) VALUES ($1, $2, $3, 'action', $3)`,
			node.String(), wf.String(), key)
		f.exec(t, `INSERT INTO workflow_node_runs (id, workflow_run_id, node_id, node_key, node_type, status)
			VALUES ($1, $2, $3, $4, 'action', $5)`, nr.String(), run.String(), node.String(), key, st)
		ids = append(ids, nr)
	}
	return run, ids
}

func (f *wfCancelFixture) nodeStatus(t *testing.T, id shared.ID) string {
	t.Helper()
	var st string
	if err := f.db.QueryRowContext(f.ctx, `SELECT status FROM workflow_node_runs WHERE id = $1`, id.String()).Scan(&st); err != nil {
		t.Fatalf("read node run: %v", err)
	}
	return st
}

func TestWorkflowRunCancel_SkipsOpenStepsTenantScopedOnce(t *testing.T) {
	f := newWFCancelFixture(t)
	runID, nodes := f.run(t, f.tenant, "completed", "running", "pending")

	// Not canceled yet: nothing is skipped.
	if n, err := f.nodes.SkipOpenNodeRuns(f.ctx, f.tenant, runID); err != nil || n != 0 {
		t.Fatalf("live run: skipped %d, %v; want 0", n, err)
	}

	run, err := f.runs.GetByTenantAndID(f.ctx, f.tenant, runID)
	if err != nil {
		t.Fatal(err)
	}
	run.Cancel()
	if err := f.runs.Update(f.ctx, run); err != nil {
		t.Fatalf("cancel: %v", err)
	}

	// Another tenant cannot close its steps, even with the id.
	stranger := seedScanTriggerTenant(f.ctx, t, f.db)
	if n, err := f.nodes.SkipOpenNodeRuns(f.ctx, stranger, runID); err != nil || n != 0 {
		t.Fatalf("cross-tenant: skipped %d, %v; want 0", n, err)
	}

	if n, err := f.nodes.SkipOpenNodeRuns(f.ctx, f.tenant, runID); err != nil || n != 2 {
		t.Fatalf("skipped %d, %v; want the running and the pending step", n, err)
	}
	if st := f.nodeStatus(t, nodes[0]); st != "completed" {
		t.Fatalf("completed step became %q", st)
	}
	for _, id := range nodes[1:] {
		if st := f.nodeStatus(t, id); st != "skipped" {
			t.Fatalf("open step = %q, want skipped", st)
		}
	}
	if n, _ := f.nodes.SkipOpenNodeRuns(f.ctx, f.tenant, runID); n != 0 {
		t.Fatalf("second pass skipped %d", n)
	}
}

// The executor still holding the run cannot overwrite the cancel, and a step
// the cancel ended cannot be started or finished afterwards.
func TestWorkflowRunCancel_LateExecutorWritesAreRefused(t *testing.T) {
	f := newWFCancelFixture(t)
	runID, nodes := f.run(t, f.tenant, "pending")

	// The executor's copies, loaded before the cancel.
	stale, err := f.runs.GetByTenantAndID(f.ctx, f.tenant, runID)
	if err != nil {
		t.Fatal(err)
	}
	staleNode, err := f.nodes.GetByID(f.ctx, nodes[0])
	if err != nil {
		t.Fatal(err)
	}

	run, _ := f.runs.GetByTenantAndID(f.ctx, f.tenant, runID)
	run.Cancel()
	if err := f.runs.Update(f.ctx, run); err != nil {
		t.Fatal(err)
	}
	if _, err := f.nodes.SkipOpenNodeRuns(f.ctx, f.tenant, runID); err != nil {
		t.Fatal(err)
	}

	staleNode.Start()
	if err := f.nodes.Update(f.ctx, staleNode); !errors.Is(err, workflow.ErrNodeRunAlreadyFinished) {
		t.Fatalf("starting a skipped step: err = %v, want ErrNodeRunAlreadyFinished", err)
	}
	stale.Complete()
	if err := f.runs.Update(f.ctx, stale); !errors.Is(err, workflow.ErrRunAlreadyFinished) {
		t.Fatalf("completing a canceled run: err = %v, want ErrRunAlreadyFinished", err)
	}
	got, _ := f.runs.GetByTenantAndID(f.ctx, f.tenant, runID)
	if got.Status != workflow.RunStatusCanceled {
		t.Fatalf("run = %q, want canceled to stand", got.Status)
	}
	if st := f.nodeStatus(t, nodes[0]); st != "skipped" {
		t.Fatalf("step = %q, want skipped to stand", st)
	}
	// An unknown run is still not found.
	ghost := *stale
	ghost.ID = shared.NewID()
	if err := f.runs.Update(f.ctx, &ghost); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown run: err = %v, want ErrNotFound", err)
	}
}
