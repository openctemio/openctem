package controller

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeExpirer struct {
	sim, live []time.Time
	batches   []int64
}

func (f *fakeExpirer) DeleteExpiredRuns(_ context.Context, simulateBefore, liveBefore time.Time, _ int) (int64, error) {
	f.sim, f.live = append(f.sim, simulateBefore), append(f.live, liveBefore)
	n := f.batches[0]
	f.batches = f.batches[1:]
	return n, nil
}

// Simulate runs go after 30 days and live runs after 180; a full batch is
// followed by another until a short one.
func TestAutomationRunRetention_CutoffsAndBatches(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	f := &fakeExpirer{batches: []int64{automationRetentionBatch, 3}}
	c := NewAutomationRunRetention(f, logger.NewNop())
	c.now = func() time.Time { return now }
	n, err := c.Reconcile(context.Background())
	if err != nil || n != automationRetentionBatch+3 || len(f.sim) != 2 {
		t.Fatalf("reconcile = %d %v after %d calls", n, err, len(f.sim))
	}
	if !f.sim[0].Equal(now.AddDate(0, 0, -30)) || !f.live[0].Equal(now.AddDate(0, 0, -180)) {
		t.Fatalf("cutoffs simulate %s live %s", f.sim[0], f.live[0])
	}
}
