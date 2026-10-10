package automation

import (
	"context"
	"errors"
	"testing"

	automationdom "github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type pauseRunRepo struct {
	automationdom.RunRepository
	outcomes []automationdom.RunStatus
}

func (r *pauseRunRepo) Update(context.Context, *automationdom.Run) error { return nil }

func (r *pauseRunRepo) LatestOutcomes(_ context.Context, _, _ shared.ID, n int) ([]automationdom.RunStatus, error) {
	if len(r.outcomes) > n {
		return r.outcomes[:n], nil
	}
	return r.outcomes, nil
}

type pauseWorkflowRepo struct {
	automationdom.WorkflowRepository
	stored  *automationdom.Workflow
	updated *automationdom.Workflow
}

func (r *pauseWorkflowRepo) GetByTenantAndID(context.Context, shared.ID, shared.ID) (*automationdom.Workflow, error) {
	cp := *r.stored
	return &cp, nil
}

func (r *pauseWorkflowRepo) Update(_ context.Context, w *automationdom.Workflow) error {
	r.updated = w
	return nil
}

func failedN(n int) []automationdom.RunStatus {
	out := make([]automationdom.RunStatus, n)
	for i := range out {
		out[i] = automationdom.RunStatusFailed
	}
	return out
}

// An automation whose latest 20 runs all failed is switched off; 19
// failures, or one success among them, keep it on.
func TestFinalizeRun_PausesAfterConsecutiveFailures(t *testing.T) {
	cases := []struct {
		name     string
		outcomes []automationdom.RunStatus
		paused   bool
	}{
		{"20 failed", failedN(maxConsecutiveFailures), true},
		{"19 failed", failedN(maxConsecutiveFailures - 1), false},
		{"a success among them", append(failedN(maxConsecutiveFailures-1), automationdom.RunStatusCompleted), false},
	}
	for _, tc := range cases {
		wf := &automationdom.Workflow{ID: shared.NewID(), TenantID: shared.NewID(), Name: "x", IsActive: true}
		wfRepo := &pauseWorkflowRepo{stored: wf}
		e := NewWorkflowExecutor(wfRepo, &pauseRunRepo{outcomes: tc.outcomes}, nil, logger.NewNop())
		run, _ := automationdom.NewRun(wf.ID, wf.TenantID, automationdom.TriggerTypeFindingCreated, nil)
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
	loaded := &automationdom.Workflow{ID: shared.NewID(), TenantID: shared.NewID(), Name: "x", IsActive: true}
	now := *loaded
	now.IsActive = false
	wfRepo := &pauseWorkflowRepo{stored: &now}
	e := NewWorkflowExecutor(wfRepo, &pauseRunRepo{}, nil, logger.NewNop())
	run, _ := automationdom.NewRun(loaded.ID, loaded.TenantID, automationdom.TriggerTypeManual, nil)
	e.finalizeRun(context.Background(), &ExecutionContext{Run: run, Workflow: loaded}, nil)
	if wfRepo.updated == nil || wfRepo.updated.IsActive {
		t.Fatal("the finishing run switched the automation back on")
	}
}
