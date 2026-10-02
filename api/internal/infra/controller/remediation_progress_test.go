package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/logger"
)

type fakeReconciler struct {
	updated int
	err     error
	calls   int
}

func (f *fakeReconciler) ReconcileProgress(_ context.Context) (int, error) {
	f.calls++
	return f.updated, f.err
}

func TestRemediationProgressController_DefaultInterval(t *testing.T) {
	c := NewRemediationProgressController(&fakeReconciler{}, 0, logger.NewNop())
	if c.Interval() != 30*time.Minute {
		t.Fatalf("expected default 30m interval, got %v", c.Interval())
	}
	if c.Name() != "remediation-progress" {
		t.Fatalf("unexpected name %q", c.Name())
	}
}

func TestRemediationProgressController_Delegates(t *testing.T) {
	r := &fakeReconciler{updated: 7}
	c := NewRemediationProgressController(r, time.Minute, logger.NewNop())

	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if n != 7 || r.calls != 1 {
		t.Fatalf("expected 7 updated in 1 call, got %d in %d", n, r.calls)
	}
}

func TestRemediationProgressController_PropagatesError(t *testing.T) {
	boom := errors.New("boom")
	c := NewRemediationProgressController(&fakeReconciler{err: boom}, time.Minute, logger.NewNop())
	if _, err := c.Reconcile(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("expected boom, got %v", err)
	}
}
