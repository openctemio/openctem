package workflow

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	workflowdom "github.com/openctemio/openctem/api/pkg/domain/workflow"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type pauseRunRepo struct {
	workflowdom.RunRepository
	outcomes []workflowdom.RunStatus
}

func (r *pauseRunRepo) Update(context.Context, *workflowdom.Run) error { return nil }

func (r *pauseRunRepo) LatestOutcomes(_ context.Context, _, _ shared.ID, n int) ([]workflowdom.RunStatus, error) {
	if len(r.outcomes) > n {
		return r.outcomes[:n], nil
	}
	return r.outcomes, nil
}

type pauseWorkflowRepo struct {
	workflowdom.WorkflowRepository
	stored  *workflowdom.Workflow
	updated *workflowdom.Workflow
}

func (r *pauseWorkflowRepo) GetByTenantAndID(context.Context, shared.ID, shared.ID) (*workflowdom.Workflow, error) {
	cp := *r.stored
	return &cp, nil
}

func (r *pauseWorkflowRepo) Update(_ context.Context, w *workflowdom.Workflow) error {
	r.updated = w
	return nil
}

func failedN(n int) []workflowdom.RunStatus {
	out := make([]workflowdom.RunStatus, n)
	for i := range out {
		out[i] = workflowdom.RunStatusFailed
	}
	return out
}

// An automation whose latest 20 runs all failed is switched off; 19
// failures, or one success among them, keep it on.
func TestFinalizeRun_PausesAfterConsecutiveFailures(t *testing.T) {
	cases := []struct {
		name     string
		outcomes []workflowdom.RunStatus
		paused   bool
	}{
		{"20 failed", failedN(maxConsecutiveFailures), true},
		{"19 failed", failedN(maxConsecutiveFailures - 1), false},
		{"a success among them", append(failedN(maxConsecutiveFailures-1), workflowdom.RunStatusCompleted), false},
	}
	for _, tc := range cases {
		wf := &workflowdom.Workflow{ID: shared.NewID(), TenantID: shared.NewID(), Name: "x", IsActive: true}
		wfRepo := &pauseWorkflowRepo{stored: wf}
		e := NewWorkflowExecutor(wfRepo, &pauseRunRepo{outcomes: tc.outcomes}, nil, logger.NewNop())
		run, _ := workflowdom.NewRun(wf.ID, wf.TenantID, workflowdom.TriggerTypeFindingCreated, nil)
		e.finalizeRun(context.Background(), &ExecutionContext{Run: run, Workflow: wf}, errors.New("step failed"))
		if wfRepo.updated == nil {
			t.Fatalf("%s: workflow stats not saved", tc.name)
		}
		if got := !wfRepo.updated.IsActive; got != tc.paused {
			t.Errorf("%s: paused = %v, want %v", tc.name, got, tc.paused)
		}
	}
}

// Statistics are written on the workflow as stored now: a switch-off made
// while the run executed is not undone by the run finishing.
func TestFinalizeRun_KeepsASwitchOffMadeDuringTheRun(t *testing.T) {
	loaded := &workflowdom.Workflow{ID: shared.NewID(), TenantID: shared.NewID(), Name: "x", IsActive: true}
	now := *loaded
	now.IsActive = false
	wfRepo := &pauseWorkflowRepo{stored: &now}
	e := NewWorkflowExecutor(wfRepo, &pauseRunRepo{}, nil, logger.NewNop())
	run, _ := workflowdom.NewRun(loaded.ID, loaded.TenantID, workflowdom.TriggerTypeManual, nil)
	e.finalizeRun(context.Background(), &ExecutionContext{Run: run, Workflow: loaded}, nil)
	if wfRepo.updated == nil || wfRepo.updated.IsActive {
		t.Fatal("the finishing run switched the automation back on")
	}
}
