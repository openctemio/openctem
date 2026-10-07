package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	workflowdom "github.com/openctemio/openctem/api/pkg/domain/workflow"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestLoopBlocked(t *testing.T) {
	wf := &workflowdom.Workflow{ID: shared.NewID()}
	other := shared.NewID()
	allow := map[string]any{"allow_automation_triggers": true}
	cases := []struct {
		name    string
		cause   *AutomationCause
		cfg     map[string]any
		blocked bool
	}{
		{"no cause", nil, nil, false},
		{"own event, even when allowed", &AutomationCause{WorkflowID: wf.ID, ChainDepth: 1}, allow, true},
		{"another automation, not allowed (default)", &AutomationCause{WorkflowID: other, ChainDepth: 1}, nil, true},
		{"another automation, allowed", &AutomationCause{WorkflowID: other, ChainDepth: MaxChainDepth}, allow, false},
		{"too deep, even when allowed", &AutomationCause{WorkflowID: other, ChainDepth: MaxChainDepth + 1}, allow, true},
	}
	for _, tc := range cases {
		if got := loopBlocked(wf, tc.cause, tc.cfg) != ""; got != tc.blocked {
			t.Errorf("%s: blocked = %v, want %v", tc.name, got, tc.blocked)
		}
	}
}

// The cause survives a JSON round trip (trigger data and scan run contexts
// are stored as JSONB), and a run's steps cause events one level deeper.
func TestAutomationCause_RoundTripAndDepth(t *testing.T) {
	c := AutomationCause{RunID: shared.NewID(), WorkflowID: shared.NewID(), ChainDepth: 2}
	raw, _ := json.Marshal(withCause(map[string]any{"x": 1}, &c))
	var back map[string]any
	_ = json.Unmarshal(raw, &back)
	got, ok := automationCauseFromData(back)
	if !ok || got != c {
		t.Fatalf("round trip = %+v %v, want %+v", got, ok, c)
	}
	run, _ := workflowdom.NewRun(shared.NewID(), shared.NewID(), workflowdom.TriggerTypeFindingStatusChanged, back)
	if s := stepCause(run); s.ChainDepth != 3 || s.WorkflowID != run.WorkflowID || s.RunID != run.ID {
		t.Fatalf("step cause = %+v, want depth 3 from this run", s)
	}
	plain, _ := workflowdom.NewRun(shared.NewID(), shared.NewID(), workflowdom.TriggerTypeManual, nil)
	if stepCause(plain).ChainDepth != 1 {
		t.Fatal("a run no automation caused is depth 0; its steps cause depth 1")
	}
}

// Two automations that undo each other ("in_progress -> confirmed" and
// "confirmed -> in_progress"), both allowing automation triggers: the
// ping-pong stops at the chain limit. Each started run is simulated by
// dispatching the status change its step makes, with the step's cause.
func TestLoopGuard_PingPongStopsAtChainDepth(t *testing.T) {
	tenant := shared.NewID()
	allow := map[string]any{"allow_automation_triggers": true}
	a := newWorkflow(tenant, workflowdom.TriggerTypeFindingStatusChanged, allow)
	b := newWorkflow(tenant, workflowdom.TriggerTypeFindingStatusChanged, allow)
	repo := &fakeWorkflowRepo{byTenant: map[shared.ID][]*workflowdom.Workflow{tenant: {a, b}}}
	f, _ := vulnerability.NewFinding(tenant, shared.NewID(), vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh, "f")

	var runs []TriggerWorkflowInput
	d := &WorkflowEventDispatcher{workflowRepo: repo, logger: logger.NewNop()}
	d.triggerFn = func(ctx context.Context, in TriggerWorkflowInput) error {
		runs = append(runs, in)
		if len(runs) > 50 {
			t.Fatal("no loop guard: runs keep starting")
		}
		run, _ := workflowdom.NewRun(in.WorkflowID, in.TenantID, in.TriggerType, in.TriggerData)
		cause := stepCause(run)
		return d.DispatchFindingEvent(ctx, FindingEvent{TenantID: tenant, Finding: f,
			EventType: workflowdom.TriggerTypeFindingStatusChanged, Cause: &cause})
	}

	// A person changes the status: both automations run (depth 0), each
	// causes an event the other runs on, and so on, until depth 3.
	if err := d.DispatchFindingEvent(context.Background(), FindingEvent{TenantID: tenant, Finding: f,
		EventType: workflowdom.TriggerTypeFindingStatusChanged}); err != nil {
		t.Fatal(err)
	}
	maxDepth := 0
	for _, r := range runs {
		depth := 0
		if c, ok := automationCauseFromData(r.TriggerData); ok {
			depth = c.ChainDepth
			if !r.SubjectCooldown {
				t.Fatal("an automation-caused run must be subject to the cooldown")
			}
			if c.WorkflowID == r.WorkflowID {
				t.Fatal("an automation ran on an event it caused itself")
			}
		}
		maxDepth = max(maxDepth, depth)
	}
	if maxDepth != MaxChainDepth {
		t.Fatalf("deepest run = %d, want the chain to stop at %d", maxDepth, MaxChainDepth)
	}
	// depth 0: a, b; each later level: one run per branch (the other one).
	if want := 2 * (MaxChainDepth + 1); len(runs) != want {
		t.Fatalf("runs = %d, want %d", len(runs), want)
	}

	// Without the opt-in, an automation-caused event starts nothing.
	runs = nil
	a.Nodes[0].Config.TriggerConfig, b.Nodes[0].Config.TriggerConfig = nil, nil
	_ = d.DispatchFindingEvent(context.Background(), FindingEvent{TenantID: tenant, Finding: f,
		EventType: workflowdom.TriggerTypeFindingStatusChanged})
	if len(runs) != 2 {
		t.Fatalf("runs = %d, want only the two runs of the person's change", len(runs))
	}
}

// "Scan finished => run the scan": the scan the automation started carries
// its cause, so its completion does not start the same automation again.
func TestLoopGuard_ScanCompletedFromItsOwnScan(t *testing.T) {
	tenant := shared.NewID()
	wf := newWorkflow(tenant, workflowdom.TriggerTypeScanCompleted, map[string]any{"allow_automation_triggers": true})
	repo := &fakeWorkflowRepo{byTenant: map[shared.ID][]*workflowdom.Workflow{tenant: {wf}}}
	rec := &triggerRecorder{}
	d := newTestDispatcher(repo, rec)

	own := AutomationCause{RunID: shared.NewID(), WorkflowID: wf.ID, ChainDepth: 1}
	run := &scanrun.Run{ID: shared.NewID(), TenantID: tenant, ScanWorkflowID: shared.NewID(), Status: scanrun.RunStatusCompleted,
		Context: runContextWithCause(WithAutomationCause(context.Background(), own), map[string]any{"targets": []any{"a"}})}
	if n := d.dispatchScanCompleted(context.Background(), run); n != 0 {
		t.Fatalf("its own scan's completion started %d runs, want 0", n)
	}
	run.Context = map[string]any{}
	if n := d.dispatchScanCompleted(context.Background(), run); n != 1 {
		t.Fatalf("a scan no automation started: %d runs, want 1", n)
	}
}

// The declared per-step limit is applied by executeNode: a step that hangs
// fails when it runs out, says so, and the run goes on.
func TestExecutor_StepTimeoutApplied(t *testing.T) {
	run, _ := workflowdom.NewRun(shared.NewID(), shared.NewID(), workflowdom.TriggerTypeManual, nil)
	e := NewWorkflowExecutor(nil, stepRunRepo{run: run}, stepNodeRuns{}, logger.NewNop())
	e.maxNodeTime = 50 * time.Millisecond
	e.conditionEvaluator = hangingEvaluator{}
	wf := &workflowdom.Workflow{ID: run.WorkflowID, TenantID: run.TenantID}
	node := &workflowdom.Node{NodeKey: "a", NodeType: workflowdom.NodeTypeCondition,
		Config: workflowdom.NodeConfig{ConditionExpr: "trigger.x == 1"}}
	nr, _ := workflowdom.NewNodeRun(run.ID, shared.NewID(), "a", workflowdom.NodeTypeCondition)
	execCtx := &ExecutionContext{Run: run, Workflow: wf, Context: map[string]any{},
		CompletedNodeKeys: map[string]bool{}, NodeRunsByKey: map[string]*workflowdom.NodeRun{"a": nr}}

	start := time.Now()
	err := e.executeNode(context.Background(), execCtx, node)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("hanging step = %v after %s, want a deadline error at ~50ms", err, time.Since(start))
	}
	if nr.Status != workflowdom.NodeRunStatusFailed || !strings.Contains(nr.ErrorMessage, "timed out") {
		t.Fatalf("step = %s %q, want failed with the timeout", nr.Status, nr.ErrorMessage)
	}
}

type stepRunRepo struct {
	workflowdom.RunRepository
	run *workflowdom.Run
}

func (r stepRunRepo) GetByTenantAndID(context.Context, shared.ID, shared.ID) (*workflowdom.Run, error) {
	return r.run, nil
}

type stepNodeRuns struct{ workflowdom.NodeRunRepository }

func (stepNodeRuns) Update(context.Context, *workflowdom.NodeRun) error { return nil }

// hangingEvaluator stands for any step that hangs until its context ends.
type hangingEvaluator struct{}

func (hangingEvaluator) Evaluate(ctx context.Context, _ string, _ map[string]any) (bool, error) {
	<-ctx.Done()
	return false, ctx.Err()
}
