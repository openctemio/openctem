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

// An Automations graph must end and every node must be able to run: the API
// refuses a cycle, a node no trigger reaches, an edge into a trigger and a
// condition edge without a yes/no handle, with a 400 and before any write.

func gTrigger(key string) automationsvc.CreateNodeInput {
	return automationsvc.CreateNodeInput{NodeKey: key, NodeType: automation.NodeTypeTrigger,
		Config: automation.NodeConfig{TriggerType: automation.TriggerTypeManual}}
}

func gAction(key string) automationsvc.CreateNodeInput {
	return automationsvc.CreateNodeInput{NodeKey: key, NodeType: automation.NodeTypeAction,
		Config: automation.NodeConfig{ActionType: automation.ActionTypeAddTags}}
}

func gCondition(key string) automationsvc.CreateNodeInput {
	return automationsvc.CreateNodeInput{NodeKey: key, NodeType: automation.NodeTypeCondition,
		Config: automation.NodeConfig{ConditionExpr: "finding.severity == 'critical'"}}
}

func gEdge(from, to, handle string) automationsvc.CreateEdgeInput {
	return automationsvc.CreateEdgeInput{SourceNodeKey: from, TargetNodeKey: to, SourceHandle: handle}
}

func assertGraphErr(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got nil", code)
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation (HTTP 400), got %v", err)
	}
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != code {
		t.Fatalf("expected code %s, got %v", code, err)
	}
}

func TestCreateWorkflow_GraphChecks(t *testing.T) {
	cases := []struct {
		name  string
		nodes []automationsvc.CreateNodeInput
		edges []automationsvc.CreateEdgeInput
		code  string // "" = accepted
	}{
		{
			name:  "chain",
			nodes: []automationsvc.CreateNodeInput{gTrigger("t"), gAction("a"), gAction("b")},
			edges: []automationsvc.CreateEdgeInput{gEdge("t", "a", ""), gEdge("a", "b", "")},
		},
		{
			name:  "condition with yes and no branches joining again",
			nodes: []automationsvc.CreateNodeInput{gTrigger("t"), gCondition("c"), gAction("y"), gAction("n"), gAction("j")},
			edges: []automationsvc.CreateEdgeInput{
				gEdge("t", "c", ""), gEdge("c", "y", "yes"), gEdge("c", "n", "no"),
				gEdge("y", "j", ""), gEdge("n", "j", ""),
			},
		},
		{
			name:  "cycle",
			nodes: []automationsvc.CreateNodeInput{gTrigger("t"), gAction("a"), gAction("b")},
			edges: []automationsvc.CreateEdgeInput{gEdge("t", "a", ""), gEdge("a", "b", ""), gEdge("b", "a", "")},
			code:  automation.ErrCodeGraphCycle,
		},
		{
			name:  "unreachable node",
			nodes: []automationsvc.CreateNodeInput{gTrigger("t"), gAction("a"), gAction("orphan")},
			edges: []automationsvc.CreateEdgeInput{gEdge("t", "a", "")},
			code:  automation.ErrCodeGraphUnreachable,
		},
		{
			name:  "edge into a trigger",
			nodes: []automationsvc.CreateNodeInput{gTrigger("t"), gTrigger("t2"), gAction("a")},
			edges: []automationsvc.CreateEdgeInput{gEdge("t", "a", ""), gEdge("a", "t2", "")},
			code:  automation.ErrCodeGraphEdge,
		},
		{
			name:  "condition edge without a handle",
			nodes: []automationsvc.CreateNodeInput{gTrigger("t"), gCondition("c"), gAction("a")},
			edges: []automationsvc.CreateEdgeInput{gEdge("t", "c", ""), gEdge("c", "a", "")},
			code:  automation.ErrCodeGraphEdge,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			service, workflowRepo, nodeRepo, edgeRepo, _ := newTestWorkflowService()
			_, err := service.CreateWorkflow(context.Background(), automationsvc.CreateWorkflowInput{
				TenantID: shared.NewID(), UserID: shared.NewID(), Name: "wf", Nodes: tc.nodes, Edges: tc.edges,
			})
			if tc.code == "" {
				if err != nil {
					t.Fatalf("valid graph refused: %v", err)
				}
				return
			}
			assertGraphErr(t, err, tc.code)
			if len(workflowRepo.workflows) != 0 || nodeRepo.GetNodeCount() != 0 || edgeRepo.GetEdgeCount() != 0 {
				t.Fatalf("refused graph was persisted")
			}
		})
	}
}

func TestUpdateWorkflowGraph_RefusesCycleBeforeDeletingGraph(t *testing.T) {
	service, workflowRepo, nodeRepo, _, _ := newTestWorkflowService()
	ctx := context.Background()
	tenantID := shared.NewID()
	wf := createTestWorkflow(tenantID, "existing")
	_ = workflowRepo.Create(ctx, wf)
	trig, _ := automation.NewNode(wf.ID, "t", automation.NodeTypeTrigger, "t")
	_ = nodeRepo.Create(ctx, trig)

	_, err := service.UpdateWorkflowGraph(ctx, automationsvc.UpdateWorkflowGraphInput{
		TenantID: tenantID, UserID: shared.NewID(), WorkflowID: wf.ID,
		Nodes: []automationsvc.CreateNodeInput{gTrigger("t"), gAction("a"), gAction("b")},
		Edges: []automationsvc.CreateEdgeInput{gEdge("t", "a", ""), gEdge("a", "b", ""), gEdge("b", "a", "")},
	})
	assertGraphErr(t, err, automation.ErrCodeGraphCycle)
	if nodeRepo.GetNodeCount() != 1 {
		t.Fatalf("existing graph was touched: %d nodes, want 1", nodeRepo.GetNodeCount())
	}
}

func TestAddEdge_RefusesCycleAndEdgeIntoTrigger(t *testing.T) {
	service, workflowRepo, nodeRepo, edgeRepo, _ := newTestWorkflowService()
	ctx := context.Background()
	tenantID := shared.NewID()
	wf := createTestWorkflow(tenantID, "edges")
	t1, _ := automation.NewNode(wf.ID, "t", automation.NodeTypeTrigger, "t")
	a, _ := automation.NewNode(wf.ID, "a", automation.NodeTypeAction, "a")
	b, _ := automation.NewNode(wf.ID, "b", automation.NodeTypeAction, "b")
	ta, _ := automation.NewEdge(wf.ID, "t", "a")
	ab, _ := automation.NewEdge(wf.ID, "a", "b")
	wf.Nodes = []*automation.Node{t1, a, b}
	wf.Edges = []*automation.Edge{ta, ab}
	_ = workflowRepo.Create(ctx, wf)
	for _, n := range wf.Nodes {
		_ = nodeRepo.Create(ctx, n)
	}

	_, err := service.AddEdge(ctx, automationsvc.AddEdgeInput{TenantID: tenantID, WorkflowID: wf.ID, SourceNodeKey: "b", TargetNodeKey: "a"})
	assertGraphErr(t, err, automation.ErrCodeGraphCycle)
	_, err = service.AddEdge(ctx, automationsvc.AddEdgeInput{TenantID: tenantID, WorkflowID: wf.ID, SourceNodeKey: "b", TargetNodeKey: "t"})
	assertGraphErr(t, err, automation.ErrCodeGraphEdge)
	if edgeRepo.GetEdgeCount() != 0 {
		t.Fatalf("refused edge was persisted")
	}
	if _, err := service.AddEdge(ctx, automationsvc.AddEdgeInput{TenantID: tenantID, WorkflowID: wf.ID, SourceNodeKey: "t", TargetNodeKey: "b"}); err != nil {
		t.Fatalf("valid edge refused: %v", err)
	}
}

func TestAddEdge_OtherTenantWorkflowNotFound(t *testing.T) {
	service, workflowRepo, _, edgeRepo, _ := newTestWorkflowService()
	ctx := context.Background()
	wf := createTestWorkflow(shared.NewID(), "theirs")
	_ = workflowRepo.Create(ctx, wf)
	_, err := service.AddEdge(ctx, automationsvc.AddEdgeInput{TenantID: shared.NewID(), WorkflowID: wf.ID, SourceNodeKey: "t", TargetNodeKey: "a"})
	if err == nil || !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant AddEdge: want not found, got %v", err)
	}
	if edgeRepo.GetEdgeCount() != 0 {
		t.Fatalf("edge written into another tenant's workflow")
	}
}

func TestActivateWorkflow_RefusesUnreachableNode(t *testing.T) {
	service, workflowRepo, _, _, _ := newTestWorkflowService()
	ctx := context.Background()
	tenantID := shared.NewID()
	wf := createTestWorkflow(tenantID, "loose")
	wf.Deactivate()
	t1, _ := automation.NewNode(wf.ID, "t", automation.NodeTypeTrigger, "t")
	a, _ := automation.NewNode(wf.ID, "a", automation.NodeTypeAction, "a")
	wf.Nodes = []*automation.Node{t1, a}
	_ = workflowRepo.Create(ctx, wf)

	on := true
	_, err := service.UpdateWorkflow(ctx, automationsvc.UpdateWorkflowInput{TenantID: tenantID, UserID: shared.NewID(), WorkflowID: wf.ID, IsActive: &on})
	assertGraphErr(t, err, automation.ErrCodeGraphUnreachable)
}

func TestWorkflowTypes_StatusChangedValidRunScriptUnsupported(t *testing.T) {
	if !automation.TriggerTypeFindingStatusChanged.IsValid() || !automation.TriggerTypeFindingStatusChanged.IsSupported() {
		t.Fatal("finding_status_changed is fired by the finding service and must be a valid, supported trigger")
	}
	if automation.ActionTypeRunScript.IsSupported() {
		t.Fatal("run_script has no sandbox and must be refused on write")
	}
	err := automation.ValidateSupported(automation.NodeConfig{ActionType: automation.ActionTypeRunScript})
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != automation.ErrCodeUnsupportedWorkflowFeature || !strings.Contains(err.Error(), "action:run_script") {
		t.Fatalf("run_script: want %s naming action:run_script, got %v", automation.ErrCodeUnsupportedWorkflowFeature, err)
	}
}
