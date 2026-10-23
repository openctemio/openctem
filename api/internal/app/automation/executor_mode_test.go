package automation

import (
	"context"
	"strings"
	"testing"

	automationdom "github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type allowAllSteps struct{}

func (allowAllSteps) AuthorizeStep(ctx context.Context, _ StepAuthorization) (context.Context, error) {
	return ctx, nil
}

type countingAction struct{ calls int }

func (c *countingAction) Execute(context.Context, *ActionInput) (map[string]any, error) {
	c.calls++
	return map[string]any{}, nil
}

type countingNotifier struct{ calls int }

func (c *countingNotifier) Send(context.Context, *NotificationInput) (map[string]any, error) {
	c.calls++
	return map[string]any{}, nil
}

// Only a live run reaches an action or notification handler: a simulate run,
// and a run whose mode is empty or unknown, only records what it would do.
func TestExecutor_OnlyLiveRunsCallHandlers(t *testing.T) {
	for _, mode := range []automationdom.Mode{automationdom.ModeSimulate, "", "LIVE", "dry"} {
		act, notify := &countingAction{}, &countingNotifier{}
		e := NewWorkflowExecutor(nil, nil, nil, logger.NewNop(), WithExecutorStepAuthorizer(allowAllSteps{}))
		e.RegisterActionHandler(automationdom.ActionTypeAddTags, act)
		e.notificationHandler = notify
		run := &automationdom.Run{ID: shared.NewID(), TenantID: shared.NewID(), Mode: mode}
		execCtx := &ExecutionContext{Run: run, Workflow: &automationdom.Workflow{ID: shared.NewID()}, Context: map[string]any{}}
		actNode := &automationdom.Node{NodeKey: "a", NodeType: automationdom.NodeTypeAction,
			Config: automationdom.NodeConfig{ActionType: automationdom.ActionTypeAddTags, ActionConfig: map[string]any{"tags": []any{"x"}}}}
		notifyNode := &automationdom.Node{NodeKey: "n", NodeType: automationdom.NodeTypeNotification,
			Config: automationdom.NodeConfig{NotificationType: automationdom.NotificationTypeSlack}}
		if _, err := e.executeActionNode(context.Background(), execCtx, actNode); err != nil {
			t.Fatalf("mode %q: action step: %v", mode, err)
		}
		if _, err := e.executeNotificationNode(context.Background(), execCtx, notifyNode); err != nil {
			t.Fatalf("mode %q: notification step: %v", mode, err)
		}
		if act.calls != 0 || notify.calls != 0 {
			t.Fatalf("mode %q: handlers called (action %d, notification %d); only a live run may act", mode, act.calls, notify.calls)
		}
	}
}

type modeRunRepo struct {
	automationdom.RunRepository
	run     *automationdom.Run
	started bool
}

func (r *modeRunRepo) GetWithNodeRuns(context.Context, shared.ID) (*automationdom.Run, error) {
	return r.run, nil
}

func (r *modeRunRepo) Update(context.Context, *automationdom.Run) error {
	r.started = true
	return nil
}

type modeWorkflowRepo struct {
	automationdom.WorkflowRepository
	wf *automationdom.Workflow
}

func (r *modeWorkflowRepo) GetWithGraph(context.Context, shared.ID) (*automationdom.Workflow, error) {
	return r.wf, nil
}

type noVersions struct {
	automationdom.VersionRepository
}

// A live run that pins no version would act on the unpublished draft: it is
// refused before it starts.
func TestExecutor_RefusesALiveRunWithoutAPinnedVersion(t *testing.T) {
	tenant := shared.NewID()
	wf := &automationdom.Workflow{ID: shared.NewID(), TenantID: tenant}
	run := &automationdom.Run{ID: shared.NewID(), TenantID: tenant, WorkflowID: wf.ID,
		Status: automationdom.RunStatusPending, Mode: automationdom.ModeLive}
	runs := &modeRunRepo{run: run}
	e := NewWorkflowExecutor(&modeWorkflowRepo{wf: wf}, runs, nil, logger.NewNop(), WithExecutorVersions(noVersions{}))
	err := e.ExecuteWithTenant(context.Background(), run.ID, tenant)
	if err == nil || !strings.Contains(err.Error(), "no pinned version") {
		t.Fatalf("err = %v, want a refusal for a live run without a version", err)
	}
	if runs.started {
		t.Fatal("the run was started")
	}
}
