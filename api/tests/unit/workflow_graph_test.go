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

// An Automations graph must end and every node must be able to run: the API
// refuses a cycle, a node no trigger reaches, an edge into a trigger and a
// condition edge without a yes/no handle, with a 400 and before any write.

func gTrigger(key string) workflowsvc.CreateNodeInput {
	return workflowsvc.CreateNodeInput{NodeKey: key, NodeType: workflow.NodeTypeTrigger,
		Config: workflow.NodeConfig{TriggerType: workflow.TriggerTypeManual}}
}

func gAction(key string) workflowsvc.CreateNodeInput {
	return workflowsvc.CreateNodeInput{NodeKey: key, NodeType: workflow.NodeTypeAction,
		Config: workflow.NodeConfig{ActionType: workflow.ActionTypeAddTags}}
}

func gCondition(key string) workflowsvc.CreateNodeInput {
	return workflowsvc.CreateNodeInput{NodeKey: key, NodeType: workflow.NodeTypeCondition,
		Config: workflow.NodeConfig{ConditionExpr: "finding.severity == 'critical'"}}
}

func gEdge(from, to, handle string) workflowsvc.CreateEdgeInput {
	return workflowsvc.CreateEdgeInput{SourceNodeKey: from, TargetNodeKey: to, SourceHandle: handle}
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
		nodes []workflowsvc.CreateNodeInput
		edges []workflowsvc.CreateEdgeInput
		code  string // "" = accepted
	}{
		{
			name:  "chain",
			nodes: []workflowsvc.CreateNodeInput{gTrigger("t"), gAction("a"), gAction("b")},
			edges: []workflowsvc.CreateEdgeInput{gEdge("t", "a", ""), gEdge("a", "b", "")},
		},
		{
			name:  "condition with yes and no branches joining again",
			nodes: []workflowsvc.CreateNodeInput{gTrigger("t"), gCondition("c"), gAction("y"), gAction("n"), gAction("j")},
			edges: []workflowsvc.CreateEdgeInput{
				gEdge("t", "c", ""), gEdge("c", "y", "yes"), gEdge("c", "n", "no"),
				gEdge("y", "j", ""), gEdge("n", "j", ""),
			},
		},
		{
			name:  "cycle",
			nodes: []workflowsvc.CreateNodeInput{gTrigger("t"), gAction("a"), gAction("b")},
			edges: []workflowsvc.CreateEdgeInput{gEdge("t", "a", ""), gEdge("a", "b", ""), gEdge("b", "a", "")},
			code:  workflow.ErrCodeGraphCycle,
		},
		{
			name:  "unreachable node",
			nodes: []workflowsvc.CreateNodeInput{gTrigger("t"), gAction("a"), gAction("orphan")},
			edges: []workflowsvc.CreateEdgeInput{gEdge("t", "a", "")},
			code:  workflow.ErrCodeGraphUnreachable,
		},
		{
			name:  "edge into a trigger",
			nodes: []workflowsvc.CreateNodeInput{gTrigger("t"), gTrigger("t2"), gAction("a")},
			edges: []workflowsvc.CreateEdgeInput{gEdge("t", "a", ""), gEdge("a", "t2", "")},
			code:  workflow.ErrCodeGraphEdge,
		},
		{
			name:  "condition edge without a handle",
			nodes: []workflowsvc.CreateNodeInput{gTrigger("t"), gCondition("c"), gAction("a")},
			edges: []workflowsvc.CreateEdgeInput{gEdge("t", "c", ""), gEdge("c", "a", "")},
			code:  workflow.ErrCodeGraphEdge,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			service, workflowRepo, nodeRepo, edgeRepo, _ := newTestWorkflowService()
			_, err := service.CreateWorkflow(context.Background(), workflowsvc.CreateWorkflowInput{
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
	trig, _ := workflow.NewNode(wf.ID, "t", workflow.NodeTypeTrigger, "t")
	_ = nodeRepo.Create(ctx, trig)

	_, err := service.UpdateWorkflowGraph(ctx, workflowsvc.UpdateWorkflowGraphInput{
		TenantID: tenantID, UserID: shared.NewID(), WorkflowID: wf.ID,
		Nodes: []workflowsvc.CreateNodeInput{gTrigger("t"), gAction("a"), gAction("b")},
		Edges: []workflowsvc.CreateEdgeInput{gEdge("t", "a", ""), gEdge("a", "b", ""), gEdge("b", "a", "")},
	})
	assertGraphErr(t, err, workflow.ErrCodeGraphCycle)
	if nodeRepo.GetNodeCount() != 1 {
		t.Fatalf("existing graph was touched: %d nodes, want 1", nodeRepo.GetNodeCount())
	}
}

func TestAddEdge_RefusesCycleAndEdgeIntoTrigger(t *testing.T) {
	service, workflowRepo, nodeRepo, edgeRepo, _ := newTestWorkflowService()
	ctx := context.Background()
	tenantID := shared.NewID()
	wf := createTestWorkflow(tenantID, "edges")
	t1, _ := workflow.NewNode(wf.ID, "t", workflow.NodeTypeTrigger, "t")
	a, _ := workflow.NewNode(wf.ID, "a", workflow.NodeTypeAction, "a")
	b, _ := workflow.NewNode(wf.ID, "b", workflow.NodeTypeAction, "b")
	ta, _ := workflow.NewEdge(wf.ID, "t", "a")
	ab, _ := workflow.NewEdge(wf.ID, "a", "b")
	wf.Nodes = []*workflow.Node{t1, a, b}
	wf.Edges = []*workflow.Edge{ta, ab}
	_ = workflowRepo.Create(ctx, wf)
	for _, n := range wf.Nodes {
		_ = nodeRepo.Create(ctx, n)
	}

	_, err := service.AddEdge(ctx, workflowsvc.AddEdgeInput{TenantID: tenantID, WorkflowID: wf.ID, SourceNodeKey: "b", TargetNodeKey: "a"})
	assertGraphErr(t, err, workflow.ErrCodeGraphCycle)
	_, err = service.AddEdge(ctx, workflowsvc.AddEdgeInput{TenantID: tenantID, WorkflowID: wf.ID, SourceNodeKey: "b", TargetNodeKey: "t"})
	assertGraphErr(t, err, workflow.ErrCodeGraphEdge)
	if edgeRepo.GetEdgeCount() != 0 {
		t.Fatalf("refused edge was persisted")
	}
	if _, err := service.AddEdge(ctx, workflowsvc.AddEdgeInput{TenantID: tenantID, WorkflowID: wf.ID, SourceNodeKey: "t", TargetNodeKey: "b"}); err != nil {
		t.Fatalf("valid edge refused: %v", err)
	}
}

func TestAddEdge_OtherTenantWorkflowNotFound(t *testing.T) {
	service, workflowRepo, _, edgeRepo, _ := newTestWorkflowService()
	ctx := context.Background()
	wf := createTestWorkflow(shared.NewID(), "theirs")
	_ = workflowRepo.Create(ctx, wf)
	_, err := service.AddEdge(ctx, workflowsvc.AddEdgeInput{TenantID: shared.NewID(), WorkflowID: wf.ID, SourceNodeKey: "t", TargetNodeKey: "a"})
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
	t1, _ := workflow.NewNode(wf.ID, "t", workflow.NodeTypeTrigger, "t")
	a, _ := workflow.NewNode(wf.ID, "a", workflow.NodeTypeAction, "a")
	wf.Nodes = []*workflow.Node{t1, a}
	_ = workflowRepo.Create(ctx, wf)

	on := true
	_, err := service.UpdateWorkflow(ctx, workflowsvc.UpdateWorkflowInput{TenantID: tenantID, UserID: shared.NewID(), WorkflowID: wf.ID, IsActive: &on})
	assertGraphErr(t, err, workflow.ErrCodeGraphUnreachable)
}

func TestWorkflowTypes_StatusChangedValidRunScriptUnsupported(t *testing.T) {
	if !workflow.TriggerTypeFindingStatusChanged.IsValid() || !workflow.TriggerTypeFindingStatusChanged.IsSupported() {
		t.Fatal("finding_status_changed is fired by the finding service and must be a valid, supported trigger")
	}
	if workflow.ActionTypeRunScript.IsSupported() {
		t.Fatal("run_script has no sandbox and must be refused on write")
	}
	err := workflow.ValidateSupported(workflow.NodeConfig{ActionType: workflow.ActionTypeRunScript})
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != workflow.ErrCodeUnsupportedWorkflowFeature || !strings.Contains(err.Error(), "action:run_script") {
		t.Fatalf("run_script: want %s naming action:run_script, got %v", workflow.ErrCodeUnsupportedWorkflowFeature, err)
	}
}
