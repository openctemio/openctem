package unit

// Every action and notification step is checked against the person the run
// acts as before it runs (research/61 P0-3). These tests drive the executor
// with recording and refusing authorizers; the checks themselves run against
// Postgres in handler/workflow_run_authz_db_test.go.

import (
	"context"
	"sync"
	"testing"

	workflowsvc "github.com/openctemio/openctem/api/internal/app/workflow"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/workflow"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type wfAuthzRecorder struct {
	mu     sync.Mutex
	reqs   []workflowsvc.StepAuthorization
	refuse error
}

func (r *wfAuthzRecorder) AuthorizeStep(ctx context.Context, req workflowsvc.StepAuthorization) (context.Context, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = append(r.reqs, req)
	return ctx, r.refuse
}

type wfAuthzFixture struct {
	executor *workflowsvc.WorkflowExecutor
	wfRepo   *wfExecMockWorkflowRepo
	runs     *wfExecMockRunRepo
	nodeRuns *wfExecMockNodeRunRepo
	handler  *wfExecMockActionHandler
	tenant   shared.ID
}

func newWfAuthzFixture(opts ...workflowsvc.WorkflowExecutorOption) *wfAuthzFixture {
	f := &wfAuthzFixture{
		wfRepo: newWfExecMockWorkflowRepo(), runs: newWfExecMockRunRepo(), nodeRuns: newWfExecMockNodeRunRepo(),
		handler: &wfExecMockActionHandler{returnOutput: map[string]any{"ok": true}}, tenant: shared.NewID(),
	}
	f.executor = workflowsvc.NewWorkflowExecutor(f.wfRepo, f.runs, f.nodeRuns, logger.NewNop(), opts...)
	f.executor.RegisterActionHandler(workflow.ActionTypeAddTags, f.handler)
	return f
}

// run executes a trigger -> add_tags workflow owned by owner, as a run of
// triggerType started by triggeredBy (nil for an event), and returns the
// action's node run.
func (f *wfAuthzFixture) run(t *testing.T, owner *shared.ID, triggerType workflow.TriggerType, triggeredBy *shared.ID, data map[string]any) *workflow.NodeRun {
	t.Helper()
	ctx := context.Background()
	wf, _ := workflow.NewWorkflow(f.tenant, "authz", "")
	if owner != nil {
		wf.SetCreatedBy(*owner)
	}
	trig, _ := workflow.NewNode(wf.ID, "t", workflow.NodeTypeTrigger, "t")
	_ = trig.SetTriggerConfig(triggerType, nil)
	act, _ := workflow.NewNode(wf.ID, "a", workflow.NodeTypeAction, "a")
	_ = act.SetActionConfig(workflow.ActionTypeAddTags, map[string]any{"tags": []any{"x"}})
	edge, _ := workflow.NewEdge(wf.ID, "t", "a")
	wf.Nodes = []*workflow.Node{trig, act}
	wf.Edges = []*workflow.Edge{edge}
	_ = f.wfRepo.Create(ctx, wf)

	run, _ := workflow.NewRun(wf.ID, f.tenant, triggerType, data)
	if triggeredBy != nil {
		run.SetTriggeredBy(*triggeredBy)
	}
	var actionRun *workflow.NodeRun
	for _, n := range wf.Nodes {
		nr, _ := workflow.NewNodeRun(run.ID, n.ID, n.NodeKey, n.NodeType)
		run.NodeRuns = append(run.NodeRuns, nr)
		_ = f.nodeRuns.Create(ctx, nr)
		if n.NodeKey == "a" {
			actionRun = nr
		}
	}
	_ = f.runs.Create(ctx, run)
	if err := f.executor.Execute(ctx, run.ID); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got, _ := f.nodeRuns.GetByID(ctx, actionRun.ID)
	return got
}

// Without an authorizer every action step is refused (fail closed).
func TestWfRunAuthz_NoAuthorizerRefusesSteps(t *testing.T) {
	f := newWfAuthzFixture()
	owner := shared.NewID()
	nr := f.run(t, &owner, workflow.TriggerTypeFindingCreated, nil, nil)
	if nr.Status != workflow.NodeRunStatusFailed || nr.ErrorCode != workflowsvc.ErrCodeRunNotAuthorized {
		t.Fatalf("step = %s/%s, want failed/%s", nr.Status, nr.ErrorCode, workflowsvc.ErrCodeRunNotAuthorized)
	}
	if f.handler.getCallCount() != 0 {
		t.Fatal("the action ran without an authorization check")
	}
}

// A refused step fails with the authorization code and never runs.
func TestWfRunAuthz_RefusedStepDoesNotRun(t *testing.T) {
	rec := &wfAuthzRecorder{refuse: shared.NewDomainError(workflowsvc.ErrCodeRunNotAuthorized, "no", shared.ErrForbidden)}
	f := newWfAuthzFixture(workflowsvc.WithExecutorStepAuthorizer(rec))
	owner := shared.NewID()
	nr := f.run(t, &owner, workflow.TriggerTypeFindingCreated, nil, nil)
	if nr.Status != workflow.NodeRunStatusFailed || nr.ErrorCode != workflowsvc.ErrCodeRunNotAuthorized {
		t.Fatalf("step = %s/%s, want failed/%s", nr.Status, nr.ErrorCode, workflowsvc.ErrCodeRunNotAuthorized)
	}
	if f.handler.getCallCount() != 0 {
		t.Fatal("a refused action ran")
	}
}

// An event run acts as the owner, a manual run as the member who started it;
// the step's permission and the run's subject are what is checked.
func TestWfRunAuthz_PrincipalAndSubject(t *testing.T) {
	rec := &wfAuthzRecorder{}
	f := newWfAuthzFixture(workflowsvc.WithExecutorStepAuthorizer(rec))
	owner, caller, finding := shared.NewID(), shared.NewID(), shared.NewID()
	data := map[string]any{"finding": map[string]any{"id": finding.String()}}

	if nr := f.run(t, &owner, workflow.TriggerTypeFindingCreated, nil, data); nr.Status != workflow.NodeRunStatusCompleted {
		t.Fatalf("event step = %s (%s)", nr.Status, nr.ErrorMessage)
	}
	if nr := f.run(t, &owner, workflow.TriggerTypeManual, &caller, data); nr.Status != workflow.NodeRunStatusCompleted {
		t.Fatalf("manual step = %s (%s)", nr.Status, nr.ErrorMessage)
	}
	// An event run of an automation with no owner asks with no principal
	// (which the production authorizer refuses).
	_ = f.run(t, nil, workflow.TriggerTypeFindingCreated, nil, data)

	if len(rec.reqs) != 3 {
		t.Fatalf("authorizations = %d, want one per action step", len(rec.reqs))
	}
	for i, want := range []shared.ID{owner, caller, {}} {
		got := rec.reqs[i]
		if got.PrincipalID != want {
			t.Errorf("run %d acts as %s, want %s", i, got.PrincipalID, want)
		}
		if got.Permission != permission.FindingsWrite {
			t.Errorf("run %d checked %q, want findings:write", i, got.Permission)
		}
		if len(got.FindingIDs) != 1 || got.FindingIDs[0] != finding {
			t.Errorf("run %d subjects = %v, want the trigger's finding", i, got.FindingIDs)
		}
		if got.TenantID != f.tenant {
			t.Errorf("run %d tenant = %s", i, got.TenantID)
		}
	}
}

// The production authorizer refuses a step with no principal before any
// lookup, and when it is not wired.
func TestWfRunAuthz_PrincipalAuthorizerFailsClosed(t *testing.T) {
	var unwired *workflowsvc.PrincipalAuthorizer
	if _, err := unwired.AuthorizeStep(context.Background(), workflowsvc.StepAuthorization{PrincipalID: shared.NewID()}); !workflowsvc.IsRunNotAuthorized(err) {
		t.Fatalf("unwired authorizer = %v, want a refusal", err)
	}
	a := workflowsvc.NewPrincipalAuthorizer(nil, nil, nil, nil)
	if _, err := a.AuthorizeStep(context.Background(), workflowsvc.StepAuthorization{}); !workflowsvc.IsRunNotAuthorized(err) {
		t.Fatalf("no principal = %v, want a refusal", err)
	}
}
