package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Deleting a scan workflow never deletes its runs (research/62 SW4). Before:
// scan_runs.scan_workflow_id was ON DELETE CASCADE, so deleting a workflow
// erased every run of it, with their steps, outputs and stage plans.

func TestRemoveScanWorkflow_RetiresAWorkflowWithRuns(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanWorkflowRepository(&DB{DB: db})
	f := seedStepHistory(ctx, t, db, true) // a completed run with two steps
	describe(ctx, t, db, f.template)

	// Another tenant cannot remove it.
	other := seedScanTriggerTenant(ctx, t, db)
	if _, err := repo.Remove(ctx, other, f.template); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("remove from another tenant: %v, want not found", err)
	}

	retired, err := repo.Remove(ctx, f.tenant, f.template)
	if err != nil || !retired {
		t.Fatalf("Remove = %v, %v; want retired", retired, err)
	}

	// The run and its steps are intact; the workflow is still readable by id
	// (the run page draws its graph) and marked retired.
	var runs, stepRuns int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM scan_runs WHERE scan_workflow_id = $1`, f.template.String()).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM scan_run_steps WHERE scan_run_id = $1`, f.run.ID.String()).Scan(&stepRuns); err != nil {
		t.Fatal(err)
	}
	if runs != 1 || stepRuns != 2 {
		t.Fatalf("after retire: %d runs, %d step runs; want 1 and 2", runs, stepRuns)
	}
	wf, err := repo.GetByTenantAndID(ctx, f.tenant, f.template)
	if err != nil || wf.RetiredAt == nil || wf.IsActive {
		t.Fatalf("retired workflow = %+v, %v", wf, err)
	}
	withSteps, err := repo.GetWithSteps(ctx, f.template)
	if err != nil || len(withSteps.Steps) != 2 {
		t.Fatalf("retired workflow keeps its steps: %v, %v", withSteps, err)
	}

	// It is not listed, and its name is free again.
	list, err := repo.List(ctx, scanworkflow.Filter{TenantID: &f.tenant}, pagination.New(1, 50))
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range list.Data {
		if w.ID == f.template {
			t.Fatal("a retired workflow is listed")
		}
	}
	all, err := repo.ListWithSystemTemplates(ctx, f.tenant, scanworkflow.Filter{}, pagination.New(1, 200))
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range all.Data {
		if w.ID == f.template {
			t.Fatal("a retired workflow is listed with the system templates")
		}
	}
	again, err := scanworkflow.NewWorkflow(f.tenant, "history probe", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, again); err != nil {
		t.Fatalf("a new workflow cannot reuse the name of a retired one: %v", err)
	}

	// Removing it again is not found (it is already gone for the tenant).
	if _, err := repo.Remove(ctx, f.tenant, f.template); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("second remove: %v, want not found", err)
	}

	// No delete can cascade the runs away any more.
	if _, err := db.ExecContext(ctx, `DELETE FROM scan_workflows WHERE id = $1`, f.template.String()); err == nil {
		t.Fatal("a workflow with runs was hard-deleted")
	}

	// Deleting the whole tenant still removes everything.
	if _, err := db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, f.tenant.String()); err != nil {
		t.Fatalf("delete tenant: %v", err)
	}
}

func TestRemoveScanWorkflow_RefusedWhileARunIsActive(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanWorkflowRepository(&DB{DB: db})
	f := seedStepHistory(ctx, t, db, false) // run still running
	describe(ctx, t, db, f.template)

	if _, err := repo.Remove(ctx, f.tenant, f.template); !errors.Is(err, scanworkflow.ErrScanWorkflowRunActive) {
		t.Fatalf("remove during a run: %v, want ErrScanWorkflowRunActive", err)
	}
	wf, err := repo.GetByTenantAndID(ctx, f.tenant, f.template)
	if err != nil || wf.RetiredAt != nil {
		t.Fatalf("workflow changed by a refused remove: %+v, %v", wf, err)
	}
	if err := NewScanRunRepository(&DB{DB: db}).UpdateStatus(ctx, f.run.ID, scanrun.RunStatusCanceled, ""); err != nil {
		t.Fatal(err)
	}
	if retired, err := repo.Remove(ctx, f.tenant, f.template); err != nil || !retired {
		t.Fatalf("remove after the run ended = %v, %v; want retired", retired, err)
	}
}

func TestRemoveScanWorkflow_DeletesAWorkflowWithoutRuns(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanWorkflowRepository(&DB{DB: db})
	tenant := seedScanTriggerTenant(ctx, t, db)
	wf, err := scanworkflow.NewWorkflow(tenant, "never ran", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, wf); err != nil {
		t.Fatal(err)
	}
	if retired, err := repo.Remove(ctx, tenant, wf.ID); err != nil || retired {
		t.Fatalf("Remove = %v, %v; want deleted", retired, err)
	}
	if _, err := repo.GetByTenantAndID(ctx, tenant, wf.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("deleted workflow still readable: %v", err)
	}
}

// describe gives the seeded workflow a description (the fixture leaves it
// NULL, which the workflow reader does not accept).
func describe(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `UPDATE scan_workflows SET description = $2 WHERE id = $1`, id.String(), ""); err != nil {
		t.Fatal(err)
	}
}
