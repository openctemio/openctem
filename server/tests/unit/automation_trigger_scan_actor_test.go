package unit

// A scan an automation's trigger_scan step starts acts as the automation's
// owner (the person the step authorization checked), not as the scan's owner:
// the scan owner's wider scope must not carry an automation member's step.

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/automation"
	automationdom "github.com/openctemio/openctem/api/pkg/domain/automation"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestAutomationTriggerScan_ActsAsTheAutomationOwner(t *testing.T) {
	svc, deps := newTestScanService()
	tenant, adminOwner, member, wf := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	deps.toolRepo.addTool("nuclei", true)
	sc := createTestScanInRepo(deps, tenant, "Admin's wide scan", scan.ScanTypeSingle)
	sc.SetCreatedBy(adminOwner) // the scan belongs to an administrator

	h := automation.NewPipelineTriggerHandler(nil, svc, logger.NewNop())
	ctx := automation.WithAutomationCause(context.Background(), automation.AutomationCause{RunID: shared.NewID(), WorkflowID: wf, NodeKey: "scan", ChainDepth: 1})
	out, err := h.Execute(ctx, &automation.ActionInput{
		TenantID: tenant, WorkflowID: wf, RunID: shared.NewID(), NodeKey: "scan",
		ActionType:   automationdom.ActionTypeTriggerScan,
		ActionConfig: map[string]any{"scan_id": sc.ID.String()},
		Principal:    member,
	})
	if err != nil {
		t.Fatalf("trigger_scan: %v", err)
	}
	if out["triggered"] != true {
		t.Fatalf("not triggered: %v", out)
	}

	var cmds []*commanddom.Command
	for _, c := range deps.commandRepo.commands {
		cmds = append(cmds, c)
	}
	if len(cmds) == 0 {
		t.Fatal("no command queued")
	}
	for _, c := range cmds {
		if c.DispatchGate == nil || c.DispatchGate.Actor != member.String() {
			t.Errorf("command acts as %+v, want the automation owner %s (not the scan owner %s)", c.DispatchGate, member, adminOwner)
		}
	}
	for _, r := range deps.runRepo.runs {
		if r.TriggeredBy != member.String() {
			t.Errorf("run triggered_by = %q, want the automation owner", r.TriggeredBy)
		}
		if _, ok := r.Context["automation_cause"]; !ok {
			t.Errorf("run lost the automation cause (the label): %v", r.Context)
		}
		if string(r.TriggerType) != "automation" {
			t.Errorf("run trigger type = %s, want automation", r.TriggerType)
		}
	}
}
