package scanrun

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
)

// How the stall repair waits before it acts (research/62 SG-10).
const (
	// stalledRunQuiet: a run with no step change for this long and nothing
	// in flight is advanced again. Longer than a normal advance takes.
	stalledRunQuiet = 2 * time.Minute
	// orphanPlanAge: a stage plan this old for a pending step with no
	// command was left by a planner that stopped before enqueueing.
	orphanPlanAge = 2 * time.Minute
	// stalledRunBatch bounds one repair pass.
	stalledRunBatch = 100
)

// RepairStalledRuns advances workflow runs that a missed wake-up left
// waiting on nothing: a chained step deferred for a report whose ingest then
// failed or expired (no "ingested" call comes), or a step whose plan was
// saved but whose commands were never created (a crash between the two).
// Each run is re-read in its own tenant and advanced as a step completion
// would; the run timeout still ends anything this cannot. Returns the runs
// advanced.
func (s *Service) RepairStalledRuns(ctx context.Context) (int, error) {
	store, ok := s.runRepo.(scanrun.StallRepairStore)
	if !ok {
		return 0, nil
	}
	now := time.Now()
	if n, err := store.ReleaseOrphanStagePlans(ctx, now.Add(-orphanPlanAge), stalledRunBatch); err != nil {
		return 0, err
	} else if n > 0 {
		s.logger.Warn("released stage plans that were never enqueued", "plans", n)
	}
	stalled, err := store.StalledRuns(ctx, now.Add(-stalledRunQuiet), stalledRunBatch)
	if err != nil {
		return 0, err
	}
	advanced := 0
	for _, st := range stalled {
		run, err := s.runRepo.GetWithStepRuns(ctx, st.RunID)
		if err != nil || run == nil || run.TenantID != st.TenantID || run.IsComplete() || run.ScanWorkflowID.IsZero() {
			continue
		}
		template, err := s.templateRepo.GetWithSteps(ctx, run.ScanWorkflowID)
		if err != nil {
			s.logger.Warn("stall repair: load the run's workflow", "run_id", run.ID.String(), "error", err)
			continue
		}
		if err := s.advanceRun(ctx, run, template); err != nil {
			s.logger.Warn("stall repair: advance", "run_id", run.ID.String(), "error", err)
			continue
		}
		s.logger.Info("advanced a stalled run", "run_id", run.ID.String(), "tenant_id", run.TenantID.String())
		advanced++
	}
	return advanced, nil
}
