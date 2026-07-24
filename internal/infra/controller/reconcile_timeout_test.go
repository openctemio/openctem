package controller

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/logger"
)

// probeController records the reconcile context's remaining budget so a test can
// assert which timeout the manager applied. It does NOT implement
// ReconcileTimeouter, so it gets the default (interval) budget.
type probeController struct {
	interval  time.Duration
	gotBudget time.Duration
}

func (c *probeController) Name() string            { return "deadline-probe" }
func (c *probeController) Interval() time.Duration { return c.interval }
func (c *probeController) Reconcile(ctx context.Context) (int, error) {
	if dl, ok := ctx.Deadline(); ok {
		c.gotBudget = time.Until(dl)
	}
	return 0, nil
}

// probeWithTimeout also implements ReconcileTimeouter to request a larger budget.
type probeWithTimeout struct {
	probeController
	timeout time.Duration
}

func (c *probeWithTimeout) ReconcileTimeout() time.Duration { return c.timeout }

func newTestManager() *Manager {
	return NewManager(&ManagerConfig{Logger: logger.NewNop()})
}

func TestReconcileOnce_DefaultBudgetIsInterval(t *testing.T) {
	m := newTestManager()
	c := &probeController{interval: 50 * time.Millisecond}

	m.reconcileOnce(context.Background(), c)

	if c.gotBudget <= 0 || c.gotBudget > 50*time.Millisecond {
		t.Fatalf("default reconcile budget = %v, want >0 and <= the 50ms interval", c.gotBudget)
	}
}

func TestReconcileOnce_ReconcileTimeouterOverridesInterval(t *testing.T) {
	m := newTestManager()
	// A short poll interval but a long per-run budget — the ingest-worker shape.
	c := &probeWithTimeout{
		probeController: probeController{interval: 50 * time.Millisecond},
		timeout:         10 * time.Second,
	}

	m.reconcileOnce(context.Background(), c)

	// The budget must track the 10s ReconcileTimeout, not the 50ms interval —
	// otherwise a batch that takes longer than a poll interval is cancelled
	// mid-flight ("context deadline exceeded").
	if c.gotBudget < 9*time.Second {
		t.Fatalf("override reconcile budget = %v, want ~10s (ReconcileTimeout, not the 50ms interval)", c.gotBudget)
	}
}

func TestReconcileOnce_NonPositiveTimeoutFallsBackToInterval(t *testing.T) {
	m := newTestManager()
	c := &probeWithTimeout{
		probeController: probeController{interval: 50 * time.Millisecond},
		timeout:         0, // opt-out signal → fall back to interval
	}

	m.reconcileOnce(context.Background(), c)

	if c.gotBudget <= 0 || c.gotBudget > 50*time.Millisecond {
		t.Fatalf("budget with zero ReconcileTimeout = %v, want fallback to the 50ms interval", c.gotBudget)
	}
}
