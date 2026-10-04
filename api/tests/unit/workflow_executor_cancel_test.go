package unit

import (
	"context"
	"sync"
	"testing"

	app "github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/workflow"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// cancelableRunRepo is the executor's run store with a cancel that lands
// while the run executes: once canceled, the run reads canceled and refuses
// writes, as the guarded postgres update does.
type cancelableRunRepo struct {
	*wfExecMockRunRepo
	mu       sync.Mutex
	canceled bool
	refused  int
}

func (r *cancelableRunRepo) cancel() {
	r.mu.Lock()
	r.canceled = true
	r.mu.Unlock()
}

func (r *cancelableRunRepo) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*workflow.Run, error) {
	run, err := r.wfExecMockRunRepo.GetByID(ctx, id)
	if err != nil || run.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *run
	if r.canceled {
		cp.Status = workflow.RunStatusCanceled
	}
	return &cp, nil
}

func (r *cancelableRunRepo) Update(ctx context.Context, run *workflow.Run) error {
	r.mu.Lock()
	if r.canceled {
		r.refused++
		r.mu.Unlock()
		return workflow.ErrRunAlreadyFinished
	}
	r.mu.Unlock()
	return r.wfExecMockRunRepo.Update(ctx, run)
}

// cancelingHandler cancels the run the first time it runs.
type cancelingHandler struct {
	wfExecMockActionHandler
	repo *cancelableRunRepo
}

func (h *cancelingHandler) Execute(ctx context.Context, input *app.ActionInput) (map[string]any, error) {
	out, err := h.wfExecMockActionHandler.Execute(ctx, input)
	h.repo.cancel()
	return out, err
}

// A run canceled while its first step runs starts no further step, and the
// executor writes no outcome over the cancel (RFC-046 §8).
func TestWfExec_CanceledRunStartsNoFurtherStep(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := &cancelableRunRepo{wfExecMockRunRepo: newWfExecMockRunRepo()}
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := app.NewWorkflowExecutor(workflowRepo, runRepo, nodeRunRepo, logger.NewNop())
	handler := &cancelingHandler{repo: runRepo}
	executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, handler)

	wf := wfExecBuildLinearWorkflow(tenantID)
	_ = workflowRepo.Create(context.Background(), wf)
	run := wfExecBuildRun(wf, tenantID)
	_ = runRepo.Create(context.Background(), run)
	for _, nr := range run.NodeRuns {
		_ = nodeRunRepo.Create(context.Background(), nr)
	}

	_ = executor.Execute(context.Background(), run.ID)

	if got := handler.getCallCount(); got != 1 {
		t.Fatalf("ran %d actions, want 1: steps after the cancel must not start", got)
	}
	runRepo.mu.Lock()
	refused := runRepo.refused
	runRepo.mu.Unlock()
	if refused != 0 {
		t.Fatalf("executor tried to write the canceled run %d time(s); it must leave the cancel alone", refused)
	}
	if wf.TotalRuns != 0 {
		t.Fatalf("a canceled run was recorded on the workflow (total runs %d)", wf.TotalRuns)
	}
}
