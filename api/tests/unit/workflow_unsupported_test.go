package unit

import (
	"context"
	"errors"
	"strings"
	"testing"

	workflowsvc "github.com/openctemio/openctem/api/internal/app/workflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/workflow"
)

// The schedule/finding_age/finding_updated/webhook triggers never fire, the
// assign_team/update_priority actions always fail at run time and
// trigger_pipeline (a scan workflow run outside any scan) is refused by design. The API must refuse to
// create, edit or activate workflows that use them (a 400: ErrValidation),
// while stored workflows that already use them stay readable and flagged.

func unsupportedCases() []struct {
	name string
	cfg  workflow.NodeConfig
	want string
} {
	return []struct {
		name string
		cfg  workflow.NodeConfig
		want string
	}{
		{"schedule trigger", workflow.NodeConfig{TriggerType: workflow.TriggerTypeSchedule}, "trigger:schedule"},
		{"finding_age trigger", workflow.NodeConfig{TriggerType: workflow.TriggerTypeFindingAge}, "trigger:finding_age"},
		{"assign_team action", workflow.NodeConfig{ActionType: workflow.ActionTypeAssignTeam}, "action:assign_team"},
		{"update_priority action", workflow.NodeConfig{ActionType: workflow.ActionTypeUpdatePriority}, "action:update_priority"},
		{"run_script action", workflow.NodeConfig{ActionType: workflow.ActionTypeRunScript}, "action:run_script"},
		{"finding_updated trigger", workflow.NodeConfig{TriggerType: workflow.TriggerTypeFindingUpdated}, "trigger:finding_updated"},
		{"webhook trigger", workflow.NodeConfig{TriggerType: workflow.TriggerTypeWebhook}, "trigger:webhook"},
		{"trigger_pipeline action", workflow.NodeConfig{ActionType: workflow.ActionTypeTriggerPipeline}, "action:trigger_pipeline"},
		{"http_request action", workflow.NodeConfig{ActionType: workflow.ActionTypeHTTPRequest}, "action:http_request"},
	}
}

func assertUnsupportedErr(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an unsupported-feature error naming %s, got nil", want)
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation (HTTP 400), got %v", err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not name %s", err.Error(), want)
	}
}

func TestWorkflowSupport_TypeSets(t *testing.T) {
	for _, tt := range unsupportedCases() {
		if got := tt.cfg.UnsupportedFeature(); got != tt.want {
			t.Errorf("%s: UnsupportedFeature() = %q, want %q", tt.name, got, tt.want)
		}
	}
	for _, tr := range []workflow.TriggerType{
		workflow.TriggerTypeManual, workflow.TriggerTypeFindingCreated, workflow.TriggerTypeFindingStatusChanged,
		workflow.TriggerTypeAssetDiscovered, workflow.TriggerTypeScanCompleted,
		workflow.TriggerTypeAITriageCompleted, workflow.TriggerTypeAITriageFailed,
	} {
		if !tr.IsSupported() {
			t.Errorf("trigger %s should be supported", tr)
		}
	}
	for _, a := range []workflow.ActionType{
		workflow.ActionTypeAssignUser, workflow.ActionTypeUpdateStatus, workflow.ActionTypeAddTags,
		workflow.ActionTypeRemoveTags, workflow.ActionTypeCreateTicket, workflow.ActionTypeUpdateTicket,
		workflow.ActionTypeTriggerScan,
		workflow.ActionTypeTriggerAITriage,
	} {
		if !a.IsSupported() {
			t.Errorf("action %s should be supported", a)
		}
	}
	if err := workflow.ValidateSupported(workflow.NodeConfig{TriggerType: workflow.TriggerTypeManual}); err != nil {
		t.Errorf("manual trigger rejected: %v", err)
	}
}

func TestCreateWorkflow_RejectsUnsupportedTypes(t *testing.T) {
	for _, tt := range unsupportedCases() {
		t.Run(tt.name, func(t *testing.T) {
			service, workflowRepo, nodeRepo, _, _ := newTestWorkflowService()
			nodes := []workflowsvc.CreateNodeInput{
				{NodeKey: "trigger_1", NodeType: workflow.NodeTypeTrigger, Config: workflow.NodeConfig{TriggerType: workflow.TriggerTypeManual}},
			}
			if tt.cfg.TriggerType != "" {
				nodes[0].Config = tt.cfg
			} else {
				nodes = append(nodes, workflowsvc.CreateNodeInput{NodeKey: "action_1", NodeType: workflow.NodeTypeAction, Config: tt.cfg})
			}

			_, err := service.CreateWorkflow(context.Background(), workflowsvc.CreateWorkflowInput{
				TenantID: shared.NewID(), UserID: shared.NewID(), Name: "wf", Nodes: nodes,
			})
			assertUnsupportedErr(t, err, tt.want)
			if len(workflowRepo.workflows) != 0 || nodeRepo.GetNodeCount() != 0 {
				t.Fatalf("rejected workflow was persisted: %d workflows, %d nodes",
					len(workflowRepo.workflows), nodeRepo.GetNodeCount())
			}
		})
	}
}

func TestUpdateWorkflowGraph_RejectsUnsupportedBeforeDeletingGraph(t *testing.T) {
	service, workflowRepo, nodeRepo, _, _ := newTestWorkflowService()
	ctx := context.Background()
	tenantID := shared.NewID()

	wf := createTestWorkflow(tenantID, "existing")
	_ = workflowRepo.Create(ctx, wf)
	trig, _ := workflow.NewNode(wf.ID, "trigger_1", workflow.NodeTypeTrigger, "t")
	trig.Config.TriggerType = workflow.TriggerTypeManual
	_ = nodeRepo.Create(ctx, trig)

	_, err := service.UpdateWorkflowGraph(ctx, workflowsvc.UpdateWorkflowGraphInput{
		TenantID: tenantID, UserID: shared.NewID(), WorkflowID: wf.ID,
		Nodes: []workflowsvc.CreateNodeInput{
			{NodeKey: "trigger_1", NodeType: workflow.NodeTypeTrigger, Config: workflow.NodeConfig{TriggerType: workflow.TriggerTypeSchedule}},
		},
	})
	assertUnsupportedErr(t, err, "trigger:schedule")
	if nodeRepo.GetNodeCount() != 1 {
		t.Fatalf("existing graph was touched: %d nodes left, want 1", nodeRepo.GetNodeCount())
	}
}

func TestAddAndUpdateNode_RejectUnsupportedTypes(t *testing.T) {
	service, workflowRepo, nodeRepo, _, _ := newTestWorkflowService()
	ctx := context.Background()
	tenantID := shared.NewID()

	wf := createTestWorkflow(tenantID, "nodes")
	_ = workflowRepo.Create(ctx, wf)

	_, err := service.AddNode(ctx, workflowsvc.AddNodeInput{
		TenantID: tenantID, WorkflowID: wf.ID, NodeKey: "a1", NodeType: workflow.NodeTypeAction,
		Config: workflow.NodeConfig{ActionType: workflow.ActionTypeAssignTeam},
	})
	assertUnsupportedErr(t, err, "action:assign_team")
	if nodeRepo.GetNodeCount() != 0 {
		t.Fatal("rejected node was persisted")
	}

	act, _ := workflow.NewNode(wf.ID, "a2", workflow.NodeTypeAction, "a2")
	act.Config.ActionType = workflow.ActionTypeUpdateStatus
	_ = nodeRepo.Create(ctx, act)

	cfg := workflow.NodeConfig{ActionType: workflow.ActionTypeUpdatePriority}
	_, err = service.UpdateNode(ctx, workflowsvc.UpdateNodeInput{
		TenantID: tenantID, WorkflowID: wf.ID, NodeID: act.ID, Config: &cfg,
	})
	assertUnsupportedErr(t, err, "action:update_priority")
	if act.Config.ActionType != workflow.ActionTypeUpdateStatus {
		t.Fatalf("node config changed to %s", act.Config.ActionType)
	}
}

func TestUpdateWorkflow_CannotActivateUnsupported_ButCanDeactivate(t *testing.T) {
	service, workflowRepo, _, _, _ := newTestWorkflowService()
	ctx := context.Background()
	tenantID := shared.NewID()

	// A stored workflow from before the rule: active, with an assign_team action.
	wf := createTestWorkflow(tenantID, "legacy")
	trig, _ := workflow.NewNode(wf.ID, "trigger_1", workflow.NodeTypeTrigger, "t")
	trig.Config.TriggerType = workflow.TriggerTypeManual
	act, _ := workflow.NewNode(wf.ID, "a1", workflow.NodeTypeAction, "a")
	act.Config.ActionType = workflow.ActionTypeAssignTeam
	wf.Nodes = []*workflow.Node{trig, act}
	_ = workflowRepo.Create(ctx, wf)

	// It stays readable and is flagged.
	got, err := service.GetWorkflow(ctx, tenantID, wf.ID)
	if err != nil {
		t.Fatalf("GetWorkflow: %v", err)
	}
	if f := got.UnsupportedFeatures(); len(f) != 1 || f[0] != "action:assign_team" {
		t.Fatalf("UnsupportedFeatures() = %v, want [action:assign_team]", f)
	}

	off, on := false, true
	if _, err := service.UpdateWorkflow(ctx, workflowsvc.UpdateWorkflowInput{TenantID: tenantID, WorkflowID: wf.ID, IsActive: &off}); err != nil {
		t.Fatalf("deactivate must be allowed: %v", err)
	}
	_, err = service.UpdateWorkflow(ctx, workflowsvc.UpdateWorkflowInput{TenantID: tenantID, WorkflowID: wf.ID, IsActive: &on})
	assertUnsupportedErr(t, err, "action:assign_team")
	if wf.IsActive {
		t.Fatal("workflow was activated")
	}

	// Renaming without activating still works.
	name := "legacy renamed"
	if _, err := service.UpdateWorkflow(ctx, workflowsvc.UpdateWorkflowInput{TenantID: tenantID, WorkflowID: wf.ID, Name: &name}); err != nil {
		t.Fatalf("rename must be allowed: %v", err)
	}
}

func TestUpdateWorkflow_ActivateOtherTenantIsNotFound(t *testing.T) {
	service, workflowRepo, _, _, _ := newTestWorkflowService()
	ctx := context.Background()

	wf := createTestWorkflow(shared.NewID(), "theirs")
	wf.Deactivate()
	_ = workflowRepo.Create(ctx, wf)

	on := true
	_, err := service.UpdateWorkflow(ctx, workflowsvc.UpdateWorkflowInput{TenantID: shared.NewID(), WorkflowID: wf.ID, IsActive: &on})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant activate: want ErrNotFound, got %v", err)
	}
	if wf.IsActive {
		t.Fatal("another tenant's workflow was activated")
	}
}

// Refusing trigger_pipeline says what to use instead.
func TestWorkflowSupport_TriggerPipelinePointsToTriggerScan(t *testing.T) {
	err := workflow.ValidateSupported(workflow.NodeConfig{ActionType: workflow.ActionTypeTriggerPipeline})
	assertUnsupportedErr(t, err, "action:trigger_pipeline")
	if !strings.Contains(err.Error(), "trigger_scan") {
		t.Fatalf("error %q does not point to trigger_scan", err.Error())
	}
}
