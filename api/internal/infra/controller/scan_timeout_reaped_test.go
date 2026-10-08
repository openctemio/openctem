package controller

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type reportingRunRepo struct {
	scanrun.RunRepository
	timedOut, unclaimed []scanrun.ReapedRun
}

func (r *reportingRunRepo) MarkTimedOutRunsReporting(context.Context) ([]scanrun.ReapedRun, error) {
	return r.timedOut, nil
}

func (r *reportingRunRepo) AbortUnclaimedRunsReporting(context.Context, time.Duration, time.Duration) ([]scanrun.ReapedRun, error) {
	return r.unclaimed, nil
}

// research/62 P0-11: a run the reaper ends (timed out, or failed because no
// sensor picked it up) is handed to the run-finished listener, so it fires
// the same event as a run that settled on its own.
func TestScanTimeoutController_ReportsReapedRuns(t *testing.T) {
	timedOut := scanrun.ReapedRun{TenantID: shared.NewID(), RunID: shared.NewID()}
	unclaimed := scanrun.ReapedRun{TenantID: shared.NewID(), RunID: shared.NewID()}
	c := NewScanTimeoutController(&reportingRunRepo{timedOut: []scanrun.ReapedRun{timedOut}, unclaimed: []scanrun.ReapedRun{unclaimed}},
		&ScanTimeoutControllerConfig{Logger: logger.NewNop()})
	var heard []scanrun.ReapedRun
	c.SetReapedRunListener(func(_ context.Context, runs []scanrun.ReapedRun) { heard = append(heard, runs...) })

	n, err := c.Reconcile(context.Background())
	if err != nil || n != 2 {
		t.Fatalf("Reconcile = %d, %v; want 2", n, err)
	}
	if len(heard) != 2 || heard[0] != unclaimed || heard[1] != timedOut {
		t.Fatalf("listener heard %v, want the unclaimed then the timed-out run", heard)
	}
}
