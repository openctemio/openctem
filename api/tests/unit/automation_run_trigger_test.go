package unit

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/workflow"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	workflowdom "github.com/openctemio/openctem/api/pkg/domain/workflow"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// research/62 P0-11: a scan an automation step starts is recorded as
// started by an automation (not "manual"), and its run names the automation,
// the automation run and the node that started it.
func TestTriggerScanAction_RunSaysAutomation(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	s := createTestScanInRepo(deps, tenantID, "Automation Scan", scan.ScanTypeSingle)
	deps.toolRepo.addTool("nuclei", true)

	automationID, automationRun := shared.NewID(), shared.NewID()
	ctx := workflow.WithAutomationCause(context.Background(),
		workflow.AutomationCause{RunID: automationRun, WorkflowID: automationID, NodeKey: "rescan", ChainDepth: 1})

	h := workflow.NewPipelineTriggerHandler(nil, svc, logger.NewNop())
	out, err := h.Execute(ctx, &workflow.ActionInput{
		TenantID:     tenantID,
		WorkflowID:   automationID,
		RunID:        automationRun,
		NodeKey:      "rescan",
		ActionType:   workflowdom.ActionTypeTriggerScan,
		ActionConfig: map[string]any{"scan_id": s.ID.String()},
	})
	if err != nil {
		t.Fatalf("trigger_scan: %v", err)
	}
	run := deps.runRepo.runs[out["run_id"].(string)]
	if run == nil {
		t.Fatalf("no run stored for %v", out)
	}
	if run.TriggerType != scanworkflow.TriggerTypeAutomation {
		t.Errorf("trigger_type = %q, want automation", run.TriggerType)
	}
	if run.TenantID != tenantID {
		t.Errorf("run tenant = %s, want the automation's tenant", run.TenantID)
	}
	cause, _ := run.Context["automation_cause"].(map[string]any)
	if cause["workflow_id"] != automationID.String() || cause["run_id"] != automationRun.String() || cause["node_key"] != "rescan" {
		t.Errorf("automation_cause = %v", cause)
	}
}

// A retry of a failed run is started by the platform: trigger_type system.
func TestRetryScanRun_RecordedAsSystem(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	s := createTestScanInRepo(deps, tenantID, "Retried Scan", scan.ScanTypeSingle)
	deps.toolRepo.addTool("nuclei", true)
	s.MaxRetries = 2

	if err := svc.RetryScanRun(context.Background(), tenantID, s.ID, 1); err != nil {
		t.Fatalf("RetryScanRun: %v", err)
	}
	if len(deps.runRepo.runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(deps.runRepo.runs))
	}
	for _, run := range deps.runRepo.runs {
		if run.TriggerType != scanworkflow.TriggerTypeSystem || run.RetryAttempt != 1 {
			t.Errorf("retry run trigger_type = %q attempt %d, want system 1", run.TriggerType, run.RetryAttempt)
		}
	}
}
