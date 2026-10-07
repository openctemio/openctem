package scanrun

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type stepUpdates struct {
	scanrun.StepRunRepository
	saved []*scanrun.StepRun
}

func (r *stepUpdates) Update(_ context.Context, sr *scanrun.StepRun) error {
	cp := *sr
	r.saved = append(r.saved, &cp)
	return nil
}

func (r *stepUpdates) GetByScanRunID(context.Context, shared.ID) ([]*scanrun.StepRun, error) {
	return nil, nil
}

type statsRunRepo struct{ scanrun.RunRepository }

func (statsRunRepo) UpdateStats(context.Context, shared.ID, int, int, int, int) error { return nil }
func (statsRunRepo) UpdateStatus(context.Context, shared.ID, scanrun.RunStatus, string) error {
	return nil
}

type oneTemplate struct {
	scanworkflow.Repository
}

func (oneTemplate) GetWithSteps(context.Context, shared.ID) (*scanworkflow.Workflow, error) {
	return &scanworkflow.Workflow{}, nil
}

// The sensor reports failures as free text under COMMAND_FAILED. The step now
// records the failure class, which is what the retry controller reads to
// never retry a run a retry cannot fix (D7).
func TestFailStep_RecordsThePermanentFailureClass(t *testing.T) {
	steps := &stepUpdates{}
	s := &Service{stepRunRepo: steps, runRepo: statsRunRepo{}, templateRepo: oneTemplate{}, logger: logger.NewNop()}
	run := &scanrun.Run{ID: shared.NewID(), TenantID: shared.NewID(), TotalSteps: 2}
	sr := scanrun.NewStepRun(run.ID, shared.NewID(), "quick_scan", 1, 3)
	run.AddStepRun(sr)

	if err := s.failStep(context.Background(), run, sr, "scanner not found: nuclei", "COMMAND_FAILED"); err != nil {
		t.Fatal(err)
	}
	if len(steps.saved) == 0 {
		t.Fatal("step not saved")
	}
	got := steps.saved[len(steps.saved)-1]
	if got.Status != scanrun.StepRunStatusFailed || got.ErrorCode != scanrun.FailureScannerNotFound {
		t.Fatalf("step saved as %s/%s, want failed/%s", got.Status, got.ErrorCode, scanrun.FailureScannerNotFound)
	}
}
