package controller

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPurgeController_RunsThePurge(t *testing.T) {
	calls := 0
	c := NewPurgeController("invitation-purge", 15*time.Minute, func(context.Context) (int64, error) {
		calls++
		return 3, nil
	}, nil)

	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if calls != 1 || n != 3 {
		t.Fatalf("purge called %d times, reported %d; want 1 call and 3 items", calls, n)
	}
	if c.Name() != "invitation-purge" || c.Interval() != 15*time.Minute {
		t.Errorf("name/interval = %q/%s", c.Name(), c.Interval())
	}
	if !c.Exclusive() {
		t.Error("a purge must hold the controller lease so one replica runs it at a time")
	}
}

func TestPurgeController_ReportsFailure(t *testing.T) {
	boom := errors.New("db down")
	c := NewPurgeController("p", time.Hour, func(context.Context) (int64, error) { return 0, boom }, nil)
	if _, err := c.Reconcile(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the purge error (the manager counts it in openctem_controller_reconcile_errors)", err)
	}
}

func TestPurgeController_DefaultInterval(t *testing.T) {
	if got := NewPurgeController("p", 0, nil, nil).Interval(); got != time.Hour {
		t.Errorf("interval = %s, want 1h when unset", got)
	}
	if n, err := NewPurgeController("p", 0, nil, nil).Reconcile(context.Background()); n != 0 || err != nil {
		t.Errorf("nil purge: %d, %v", n, err)
	}
}
