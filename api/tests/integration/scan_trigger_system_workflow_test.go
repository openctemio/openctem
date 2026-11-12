package integration

import (
	"context"
	"errors"
	"strings"
	"testing"

	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// deepReconWorkflowID is the seeded "Deep recon" system template: stored
// under the platform's system tenant, with optional steps on capabilities no
// tool implements yet (detect.services, fingerprint.tech).
const deepReconWorkflowID = "a0000002-0000-0000-0000-000000000015"

func seedWorkflowScan(ctx context.Context, t *testing.T, tenantID shared.ID, workflowID, status string) shared.ID {
	t.Helper()
	db := openLifecycleDB(t)
	scanID := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scans (id, tenant_id, name, scan_type, scan_workflow_id, targets,
		                    status, schedule_type, sensor_preference, timeout_seconds, intensity)
		 VALUES ($1, $2, $3, 'workflow', $4, ARRAY['example.test', 'www.example.test'],
		         $5, 'manual', 'tenant', 3600, 'intrusive')`,
		scanID.String(), tenantID.String(), "workflow scan "+scanID.String(), workflowID, status); err != nil {
		t.Fatalf("seed workflow scan: %v", err)
	}
	return scanID
}

// A paused workflow scan on a system template (stored under the system
// tenant, not the scan's) runs on Run now. The template's optional steps
// whose capability no tool implements are skipped with the reason; before,
// the tool lookup's not-found escaped and Run now answered "Scan not found".
func TestTriggerWorkflow_SystemTemplateWithPlannedOptionalSteps(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()

	var owner string
	if err := db.QueryRowContext(ctx,
		`SELECT tenant_id::text FROM scan_workflows WHERE id = $1 AND is_system_template AND is_active AND retired_at IS NULL`,
		deepReconWorkflowID).Scan(&owner); err != nil {
		t.Skipf("Deep recon system template not seeded: %v", err)
	}

	tenantID := seedLifecycleTenant(ctx, t, db)
	if owner == tenantID.String() {
		t.Fatal("precondition: the template must be stored under another tenant")
	}
	scanID := seedWorkflowScan(ctx, t, tenantID, deepReconWorkflowID, "paused")

	run, err := newTriggerService(db).TriggerScan(ctx, scansvc.TriggerScanExecInput{
		TenantID:    tenantID.String(),
		ScanID:      scanID.String(),
		TriggeredBy: shared.NewID().String(),
		Interactive: true,
	})
	if err != nil {
		t.Fatalf("TriggerScan: %v (not found: %v)", err, errors.Is(err, shared.ErrNotFound))
	}
	if run.ScanWorkflowID.String() != deepReconWorkflowID {
		t.Fatalf("run workflow %s, want the system template", run.ScanWorkflowID)
	}
	// Every step of the template has its step run (the optional steps
	// without a tool are skipped with the reason when their turn comes).
	var steps, wantSteps int
	var status string
	if err := db.QueryRowContext(ctx,
		`SELECT (SELECT count(*) FROM scan_run_steps WHERE scan_run_id = $1),
		        (SELECT count(*) FROM scan_workflow_steps WHERE scan_workflow_id = $2),
		        (SELECT status FROM scan_runs WHERE id = $1)`,
		run.ID.String(), deepReconWorkflowID).Scan(&steps, &wantSteps, &status); err != nil {
		t.Fatalf("read the run: %v", err)
	}
	if steps != wantSteps || run.TotalSteps != wantSteps {
		t.Errorf("%d step runs (total %d), want %d", steps, run.TotalSteps, wantSteps)
	}
	if status != "running" && status != "pending" {
		t.Errorf("run status %q, want started", status)
	}
	// The steps no tool here runs are recorded skipped with their code and
	// reason, never failed (a run goes as far as the tools support).
	var skipped, failed int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FILTER (WHERE status = 'skipped' AND error_code = 'NO_MATCHING_TOOL' AND skip_reason <> ''),
		        count(*) FILTER (WHERE status = 'failed')
		   FROM scan_run_steps WHERE scan_run_id = $1`, run.ID.String()).Scan(&skipped, &failed); err != nil {
		t.Fatalf("read the step runs: %v", err)
	}
	if skipped == 0 || failed != 0 {
		t.Errorf("%d step(s) skipped with NO_MATCHING_TOOL and a reason, %d failed; want some skipped and none failed", skipped, failed)
	}
}

// Another organization's private workflow is never run through a scan that
// names it (a scan row edited in the database, or saved by an old bug):
// PIPELINE_NOT_FOUND, recorded as a blocked run, nothing dispatched, and the
// refusal names no step or tool of that workflow.
func TestTriggerWorkflow_OtherTenantsPrivateWorkflowRefused(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenantID := seedLifecycleTenant(ctx, t, db)
	other := seedLifecycleTenant(ctx, t, db)

	foreign := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scan_workflows (id, tenant_id, name, description, is_active) VALUES ($1, $2, 'private of another org', '', TRUE)`,
		foreign.String(), other.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, tool) VALUES ($1, $2, 'secretstep', 'Secret', '', 1, 'nuclei')`,
		shared.NewID().String(), foreign.String()); err != nil {
		t.Fatal(err)
	}
	scanID := seedWorkflowScan(ctx, t, tenantID, foreign.String(), "active")

	_, err := newTriggerService(db).TriggerScan(ctx, scansvc.TriggerScanExecInput{
		TenantID:    tenantID.String(),
		ScanID:      scanID.String(),
		TriggeredBy: shared.NewID().String(),
		Interactive: true,
	})
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != scansvc.CodePipelineNotFound {
		t.Fatalf("err = %v, want %s", err, scansvc.CodePipelineNotFound)
	}
	for _, leak := range []string{"secretstep", "nuclei", "private of another org"} {
		if strings.Contains(strings.ToLower(de.Message), strings.ToLower(leak)) {
			t.Errorf("refusal %q names %q of the other organization's workflow", de.Message, leak)
		}
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM commands WHERE tenant_id = $1`, tenantID); n != 0 {
		t.Fatalf("%d command(s) dispatched for another organization's workflow", n)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM scan_runs WHERE tenant_id = $1 AND status <> 'blocked'`, tenantID); n != 0 {
		t.Fatalf("%d run(s) started for another organization's workflow", n)
	}
	var code string
	if err := db.QueryRowContext(ctx,
		`SELECT refusal_code FROM scan_runs WHERE tenant_id = $1 AND scan_id = $2 AND status = 'blocked'`,
		tenantID.String(), scanID.String()).Scan(&code); err != nil || code != scansvc.CodePipelineNotFound {
		t.Fatalf("blocked run code %q (%v), want %s", code, err, scansvc.CodePipelineNotFound)
	}
}

// No active tool with the capabilities is nil, nil (the planner answers
// NO_MATCHING_TOOL), not a not-found error.
func TestToolRepository_FindByCapabilitiesNoMatch(t *testing.T) {
	db := openLifecycleDB(t)
	got, err := postgres.NewToolRepository(&postgres.DB{DB: db}).FindByCapabilities(context.Background(), shared.NewID(), []string{"capability.nobody.implements"})
	if err != nil || got != nil {
		t.Fatalf("got %v, %v; want nil, nil", got, err)
	}
}
