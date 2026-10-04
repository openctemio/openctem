package controller

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type reaperRunRepo struct {
	pipeline.RunRepository
	timedOut, aborted int64
}

func (r *reaperRunRepo) MarkTimedOutRuns(context.Context) (int64, error) { return r.timedOut, nil }
func (r *reaperRunRepo) AbortUnclaimedRuns(context.Context, time.Duration, time.Duration) (int64, error) {
	return r.aborted, nil
}

// The reaper's work is observable (RFC-046 §12): runs it ended, by reason,
// with no tenant or run label.
func TestScanTimeoutController_CountsReapedRuns(t *testing.T) {
	deadline := metrics.ScanRunsReapedTotal.WithLabelValues("deadline")
	unclaimed := metrics.ScanRunsReapedTotal.WithLabelValues("unclaimed")
	d0, u0 := testutil.ToFloat64(deadline), testutil.ToFloat64(unclaimed)

	c := NewScanTimeoutController(&reaperRunRepo{timedOut: 3, aborted: 2},
		&ScanTimeoutControllerConfig{Logger: logger.NewNop()})
	n, err := c.Reconcile(context.Background())
	if err != nil || n != 5 {
		t.Fatalf("Reconcile = %d, %v; want 5", n, err)
	}
	if got := testutil.ToFloat64(deadline) - d0; got != 3 {
		t.Fatalf("deadline reaps counted %v, want 3", got)
	}
	if got := testutil.ToFloat64(unclaimed) - u0; got != 2 {
		t.Fatalf("unclaimed reaps counted %v, want 2", got)
	}
}
