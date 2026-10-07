package controller

import (
	"context"
	"testing"
	"time"
)

type fakeStaleRuns struct {
	before time.Time
	reason string
}

func (f *fakeStaleRuns) FailStaleRuns(_ context.Context, before time.Time, reason string) (int64, error) {
	f.before, f.reason = before, reason
	return 3, nil
}

// The reaper ends runs older than an hour (the default), with a reason.
func TestAutomationRunReaper_EndsRunsOlderThanTheCutoff(t *testing.T) {
	repo := &fakeStaleRuns{}
	c := NewAutomationRunReaper(repo, 0, nil)
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	n, err := c.Reconcile(context.Background())
	if err != nil || n != 3 {
		t.Fatalf("Reconcile = %d, %v", n, err)
	}
	if !repo.before.Equal(now.Add(-time.Hour)) || repo.reason == "" {
		t.Fatalf("cutoff %s reason %q, want one hour before now and a reason", repo.before, repo.reason)
	}
	if !c.Exclusive() || c.Interval() != 15*time.Minute {
		t.Fatal("the reaper runs on one replica every 15 minutes")
	}
}
