package scanrun

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type resultRunRepo struct {
	scanrun.RunRepository
	run *scanrun.Run
}

func (r *resultRunRepo) GetByTenantAndID(context.Context, shared.ID, shared.ID) (*scanrun.Run, error) {
	return r.run, nil
}
func (r *resultRunRepo) Update(_ context.Context, run *scanrun.Run) error { r.run = run; return nil }

type resultStepRepo struct {
	scanrun.StepRunRepository
	steps []*scanrun.StepRun
}

func (r *resultStepRepo) GetByScanRunID(context.Context, shared.ID) ([]*scanrun.StepRun, error) {
	return r.steps, nil
}
func (r *resultStepRepo) Update(context.Context, *scanrun.StepRun) error { return nil }

// A retest that concluded "inconclusive" completes its run and step (the
// tool did its work) and carries the result for the console: never failed.
func TestFinishRetestRunResultCompletes(t *testing.T) {
	run := &scanrun.Run{ID: shared.NewID(), TenantID: shared.NewID(), Status: scanrun.RunStatusRunning}
	step := scanrun.NewStepRun(run.ID, shared.ID{}, "retest", 1, 0)
	runs, steps := &resultRunRepo{run: run}, &resultStepRepo{steps: []*scanrun.StepRun{step}}
	s := &Service{runRepo: runs, stepRunRepo: steps, logger: logger.NewNop()}

	if err := s.FinishRetestRunResult(context.Background(), run.TenantID, run.ID, "inconclusive", "endpoint_mismatch"); err != nil {
		t.Fatal(err)
	}
	if runs.run.Status != scanrun.RunStatusCompleted || runs.run.FailedSteps != 0 || runs.run.ErrorMessage != "" {
		t.Fatalf("run %+v", runs.run)
	}
	res, _ := runs.run.Context[RunContextResult].(map[string]any)
	if res["kind"] != "inconclusive" || res["code"] != "endpoint_mismatch" {
		t.Fatalf("run result %+v", runs.run.Context)
	}
	if step.Status != scanrun.StepRunStatusCompleted || step.Output[StepOutputResultCode] != "endpoint_mismatch" || step.ErrorCode != "" {
		t.Fatalf("step %+v", step)
	}
}
