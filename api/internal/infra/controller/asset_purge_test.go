package controller

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakePurger struct {
	batches []int
	calls   int
	cutoff  time.Time
	err     error
}

func (f *fakePurger) PurgeDeleted(_ context.Context, before time.Time, _ int) (int, error) {
	f.cutoff = before
	if f.err != nil {
		return 0, f.err
	}
	if f.calls >= len(f.batches) {
		f.calls++
		return 0, nil
	}
	n := f.batches[f.calls]
	f.calls++
	return n, nil
}

func TestAssetPurge_BatchesUntilShortAndUsesRetention(t *testing.T) {
	now := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	p := &fakePurger{batches: []int{2, 2, 1}}
	c := NewAssetPurgeController(p, &AssetPurgeConfig{BatchSize: 2, RetentionDays: 30})
	c.now = func() time.Time { return now }

	n, err := c.Reconcile(context.Background())
	if err != nil || n != 5 || p.calls != 3 {
		t.Fatalf("Reconcile = %d, %v after %d calls; want 5 in 3 batches", n, err, p.calls)
	}
	if want := now.AddDate(0, 0, -30); !p.cutoff.Equal(want) {
		t.Errorf("cutoff = %v, want %v", p.cutoff, want)
	}
}

func TestAssetPurge_StopsOnError(t *testing.T) {
	p := &fakePurger{err: errors.New("boom")}
	c := NewAssetPurgeController(p, nil)
	if _, err := c.Reconcile(context.Background()); err == nil {
		t.Fatal("want the repository error")
	}
	if c.Interval() != 24*time.Hour || c.config.RetentionDays != 30 {
		t.Errorf("defaults: interval %v retention %d", c.Interval(), c.config.RetentionDays)
	}
}
