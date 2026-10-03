package pipeline

import (
	"context"
	"testing"

	pipelinedom "github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type stepUpdates struct {
	pipelinedom.StepRunRepository
	saved []*pipelinedom.StepRun
}

func (r *stepUpdates) Update(_ context.Context, sr *pipelinedom.StepRun) error {
	cp := *sr
	r.saved = append(r.saved, &cp)
	return nil
}

func (r *stepUpdates) GetByPipelineRunID(context.Context, shared.ID) ([]*pipelinedom.StepRun, error) {
	return nil, nil
}

type statsRunRepo struct{ pipelinedom.RunRepository }

func (statsRunRepo) UpdateStats(context.Context, shared.ID, int, int, int, int) error { return nil }
func (statsRunRepo) UpdateStatus(context.Context, shared.ID, pipelinedom.RunStatus, string) error {
	return nil
}

type oneTemplate struct{ pipelinedom.TemplateRepository }

func (oneTemplate) GetWithSteps(context.Context, shared.ID) (*pipelinedom.Template, error) {
	return &pipelinedom.Template{}, nil
}

// The sensor reports failures as free text under COMMAND_FAILED. The step now
// records the failure class, which is what the retry controller reads to
// never retry a run a retry cannot fix (D7).
func TestFailStep_RecordsThePermanentFailureClass(t *testing.T) {
	steps := &stepUpdates{}
	s := &Service{stepRunRepo: steps, runRepo: statsRunRepo{}, templateRepo: oneTemplate{}, logger: logger.NewNop()}
	run := &pipelinedom.Run{ID: shared.NewID(), TenantID: shared.NewID(), TotalSteps: 2}
	sr := pipelinedom.NewStepRun(run.ID, shared.NewID(), "quick_scan", 1, 3)
	run.AddStepRun(sr)

	if err := s.failStep(context.Background(), run, sr, "scanner not found: nuclei", "COMMAND_FAILED"); err != nil {
		t.Fatal(err)
	}
	if len(steps.saved) == 0 {
		t.Fatal("step not saved")
	}
	got := steps.saved[len(steps.saved)-1]
	if got.Status != pipelinedom.StepRunStatusFailed || got.ErrorCode != pipelinedom.FailureScannerNotFound {
		t.Fatalf("step saved as %s/%s, want failed/%s", got.Status, got.ErrorCode, pipelinedom.FailureScannerNotFound)
	}
}
