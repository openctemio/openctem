package controller

import (
	"context"
	"testing"
	"time"
)

type fakeHoldReleaser struct{ limit int }

func (f *fakeHoldReleaser) ReleaseDue(_ context.Context, limit int) (int, error) {
	f.limit = limit
	return 0, nil
}

// The release job runs on one replica at a time: two replicas listing the
// same due holds would both file the issue.
func TestTicketHoldReleaseController_ExclusiveAndBounded(t *testing.T) {
	r := &fakeHoldReleaser{}
	c := NewTicketHoldReleaseController(r, nil, 0, 0, nil)
	if !c.Exclusive() || c.Interval() != 2*time.Minute || c.Name() != "ticket-hold-release" {
		t.Fatalf("exclusive %v interval %v name %q", c.Exclusive(), c.Interval(), c.Name())
	}
	if _, err := c.Reconcile(context.Background()); err != nil || r.limit != 200 {
		t.Fatalf("limit %d err %v", r.limit, err)
	}
}

// A batch of tracker calls outlasts the 2-minute interval: the controller asks
// for a longer reconcile budget.
func TestTicketHoldRelease_HasALongerReconcileBudget(t *testing.T) {
	var c Controller = NewTicketHoldReleaseController(nil, nil, 0, 0, nil)
	rt, ok := c.(ReconcileTimeouter)
	if !ok {
		t.Fatal("the controller does not implement ReconcileTimeouter")
	}
	if got := rt.ReconcileTimeout(); got < 10*time.Minute {
		t.Fatalf("reconcile timeout = %v, want at least 10m", got)
	}
}
