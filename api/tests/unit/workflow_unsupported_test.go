package unit

import (
	"context"
	"errors"
	"strings"
	"testing"

	automationsvc "github.com/openctemio/openctem/api/internal/app/automation"
	"github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The schedule/finding_age/finding_updated/webhook triggers never fire, the
// assign_team/update_priority actions always fail at run time and
// trigger_pipeline (a scan workflow run outside any scan) is refused by design. The API must refuse to
// create, edit or activate workflows that use them (a 400: ErrValidation),
// while stored workflows that already use them stay readable and flagged.

func unsupportedCases() []struct {
	name string
	cfg  automation.NodeConfig
	want string
} {
	return []struct {
		name string
		cfg  automation.NodeConfig
		want string
	}{
		{"schedule trigger", automation.NodeConfig{TriggerType: automation.TriggerTypeSchedule}, "trigger:schedule"},
		{"finding_age trigger", automation.NodeConfig{TriggerType: automation.TriggerTypeFindingAge}, "trigger:finding_age"},
		{"assign_team action", automation.NodeConfig{ActionType: automation.ActionTypeAssignTeam}, "action:assign_team"},
		{"update_priority action", automation.NodeConfig{ActionType: automation.ActionTypeUpdatePriority}, "action:update_priority"},
		{"run_script action", automation.NodeConfig{ActionType: automation.ActionTypeRunScript}, "action:run_script"},
		{"finding_updated trigger", automation.NodeConfig{TriggerType: automation.TriggerTypeFindingUpdated}, "trigger:finding_updated"},
		{"webhook trigger", automation.NodeConfig{TriggerType: automation.TriggerTypeWebhook}, "trigger:webhook"},
		{"trigger_pipeline action", automation.NodeConfig{ActionType: automation.ActionTypeTriggerPipeline}, "action:trigger_pipeline"},
		{"http_request action", automation.NodeConfig{ActionType: automation.ActionTypeHTTPRequest}, "action:http_request"},
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
	for _, tr := range []automation.TriggerType{
		automation.TriggerTypeManual, automation.TriggerTypeFindingCreated, automation.TriggerTypeFindingStatusChanged,
		automation.TriggerTypeAssetDiscovered, automation.TriggerTypeScanCompleted,
		automation.TriggerTypeAITriageCompleted, automation.TriggerTypeAITriageFailed,
	} {
		if !tr.IsSupported() {
			t.Errorf("trigger %s should be supported", tr)
		}
	}
	for _, a := range []automation.ActionType{
		automation.ActionTypeAssignUser, automation.ActionTypeUpdateStatus, automation.ActionTypeAddTags,
		automation.ActionTypeRemoveTags, automation.ActionTypeCreateTicket, automation.ActionTypeUpdateTicket,
		automation.ActionTypeTriggerScan,
		automation.ActionTypeTriggerAITriage,
	} {
		if !a.IsSupported() {
			t.Errorf("action %s should be supported", a)
		}
	}
	if err := automation.ValidateSupported(automation.NodeConfig{TriggerType: automation.TriggerTypeManual}); err != nil {
		t.Errorf("manual trigger rejected: %v", err)
	}
}

func TestCreateWorkflow_RejectsUnsupportedTypes(t *testing.T) {
	for _, tt := range unsupportedCases() {
		t.Run(tt.name, func(t *testing.T) {
			service, workflowRepo, nodeRepo, _, _ := newTestWorkflowService()
			nodes := []automationsvc.CreateNodeInput{
				{NodeKey: "trigger_1", NodeType: automation.NodeTypeTrigger, Config: automation.NodeConfig{TriggerType: automation.TriggerTypeManual}},
			}
			if tt.cfg.TriggerType != "" {
				nodes[0].Config = tt.cfg
			} else {
				nodes = append(nodes, automationsvc.CreateNodeInput{NodeKey: "action_1", NodeType: automation.NodeTypeAction, Config: tt.cfg})
			}

			_, err := service.CreateWorkflow(context.Background(), automationsvc.CreateWorkflowInput{
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
	trig, _ := automation.NewNode(wf.ID, "trigger_1", automation.NodeTypeTrigger, "t")
	trig.Config.TriggerType = automation.TriggerTypeManual
	_ = nodeRepo.Create(ctx, trig)

	_, err := service.UpdateWorkflowGraph(ctx, automationsvc.UpdateWorkflowGraphInput{
		TenantID: tenantID, UserID: shared.NewID(), WorkflowID: wf.ID,
		Nodes: []automationsvc.CreateNodeInput{
			{NodeKey: "trigger_1", NodeType: automation.NodeTypeTrigger, Config: automation.NodeConfig{TriggerType: automation.TriggerTypeSchedule}},
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

	_, err := service.AddNode(ctx, automationsvc.AddNodeInput{
		TenantID: tenantID, WorkflowID: wf.ID, NodeKey: "a1", NodeType: automation.NodeTypeAction,
		Config: automation.NodeConfig{ActionType: automation.ActionTypeAssignTeam},
	})
	assertUnsupportedErr(t, err, "action:assign_team")
	if nodeRepo.GetNodeCount() != 0 {
		t.Fatal("rejected node was persisted")
	}

	act, _ := automation.NewNode(wf.ID, "a2", automation.NodeTypeAction, "a2")
	act.Config.ActionType = automation.ActionTypeUpdateStatus
	_ = nodeRepo.Create(ctx, act)

	cfg := automation.NodeConfig{ActionType: automation.ActionTypeUpdatePriority}
	_, err = service.UpdateNode(ctx, automationsvc.UpdateNodeInput{
		TenantID: tenantID, WorkflowID: wf.ID, NodeID: act.ID, Config: &cfg,
	})
	assertUnsupportedErr(t, err, "action:update_priority")
	if act.Config.ActionType != automation.ActionTypeUpdateStatus {
		t.Fatalf("node config changed to %s", act.Config.ActionType)
	}
}

func TestUpdateWorkflow_CannotActivateUnsupported_ButCanDeactivate(t *testing.T) {
	service, workflowRepo, _, _, _ := newTestWorkflowService()
	ctx := context.Background()
	tenantID := shared.NewID()

	// A stored workflow from before the rule: active, with an assign_team action.
	wf := createTestWorkflow(tenantID, "legacy")
	trig, _ := automation.NewNode(wf.ID, "trigger_1", automation.NodeTypeTrigger, "t")
	trig.Config.TriggerType = automation.TriggerTypeManual
	act, _ := automation.NewNode(wf.ID, "a1", automation.NodeTypeAction, "a")
	act.Config.ActionType = automation.ActionTypeAssignTeam
	wf.Nodes = []*automation.Node{trig, act}
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
	if _, err := service.UpdateWorkflow(ctx, automationsvc.UpdateWorkflowInput{TenantID: tenantID, WorkflowID: wf.ID, IsActive: &off}); err != nil {
		t.Fatalf("deactivate must be allowed: %v", err)
	}
	_, err = service.UpdateWorkflow(ctx, automationsvc.UpdateWorkflowInput{TenantID: tenantID, WorkflowID: wf.ID, IsActive: &on})
	assertUnsupportedErr(t, err, "action:assign_team")
	if wf.IsActive {
		t.Fatal("workflow was activated")
	}

	// Renaming without activating still works.
	name := "legacy renamed"
	if _, err := service.UpdateWorkflow(ctx, automationsvc.UpdateWorkflowInput{TenantID: tenantID, WorkflowID: wf.ID, Name: &name}); err != nil {
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
	_, err := service.UpdateWorkflow(ctx, automationsvc.UpdateWorkflowInput{TenantID: shared.NewID(), WorkflowID: wf.ID, IsActive: &on})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant activate: want ErrNotFound, got %v", err)
	}
	if wf.IsActive {
		t.Fatal("another tenant's workflow was activated")
	}
}

// A scan_completed status_filter must name scan outcomes: anything else
// would make the trigger silently never fire.
func TestValidateTriggerConfig_ScanStatusFilter(t *testing.T) {
	cfg := func(v any) automation.NodeConfig {
		return automation.NodeConfig{TriggerType: automation.TriggerTypeScanCompleted, TriggerConfig: map[string]any{"status_filter": v}}
	}
	for _, ok := range []automation.NodeConfig{
		{TriggerType: automation.TriggerTypeScanCompleted},
		cfg([]any{"completed"}), cfg([]any{"partial", "failed"}), cfg([]any{}),
	} {
		if err := automation.ValidateTriggerConfig(ok); err != nil {
			t.Errorf("%v refused: %v", ok.TriggerConfig, err)
		}
	}
	for _, bad := range []automation.NodeConfig{cfg([]any{"success"}), cfg("failed"), cfg([]any{1})} {
		err := automation.ValidateTriggerConfig(bad)
		if err == nil || !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%v accepted (err %v), want a 400", bad.TriggerConfig, err)
		}
	}
}

// Refusing trigger_pipeline says what to use instead.
func TestWorkflowSupport_TriggerPipelinePointsToTriggerScan(t *testing.T) {
	err := automation.ValidateSupported(automation.NodeConfig{ActionType: automation.ActionTypeTriggerPipeline})
	assertUnsupportedErr(t, err, "action:trigger_pipeline")
	if !strings.Contains(err.Error(), "trigger_scan") {
		t.Fatalf("error %q does not point to trigger_scan", err.Error())
	}
}
