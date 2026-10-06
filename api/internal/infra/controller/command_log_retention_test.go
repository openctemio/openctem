package controller

import (
	"context"
	"testing"
	"time"
)

type fakeCommandLogStore struct {
	cutoffs []time.Time
	left    int64
}

func (f *fakeCommandLogStore) DeleteOlderThan(_ context.Context, before time.Time, limit int) (int64, error) {
	f.cutoffs = append(f.cutoffs, before)
	n := min(f.left, int64(limit))
	f.left -= n
	return n, nil
}

func TestCommandLogRetention_DeletesPastFourteenDaysInBatches(t *testing.T) {
	store := &fakeCommandLogStore{left: commandLogBatchSize + 10}
	c := NewCommandLogRetentionController(store, 0, nil)
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }

	n, err := c.Reconcile(context.Background())
	if err != nil || n != commandLogBatchSize+10 {
		t.Fatalf("deleted %d, %v", n, err)
	}
	if len(store.cutoffs) != 2 || !store.cutoffs[0].Equal(now.Add(-14*24*time.Hour)) {
		t.Fatalf("cutoffs %v", store.cutoffs)
	}
	if !c.Exclusive() || c.Name() != "command-log-retention" {
		t.Fatal("must run on one replica")
	}
}
