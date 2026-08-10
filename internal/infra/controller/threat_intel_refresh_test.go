package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// enqueueReclassify is the seam the daily KEV pass uses to push a
// ReasonKEVRefresh request per tenant whose findings were escalated/flagged, so
// their priority_class is recomputed. These tests pin its contract directly
// (Reconcile itself calls the network-backed IntelService.SyncAll).

func TestKEVRefresh_EnqueuesPerTenant(t *testing.T) {
	q := &captureQueue{}
	c := NewThreatIntelRefreshController(nil, nil, q, logger.NewNop())

	t1, t2 := shared.NewID(), shared.NewID()
	c.enqueueReclassify(context.Background(), []shared.ID{t1, t2})

	if len(q.reqs) != 2 {
		t.Fatalf("want 2 enqueued requests, got %d", len(q.reqs))
	}
	for _, r := range q.reqs {
		if r.Reason != ReasonKEVRefresh {
			t.Errorf("wrong reason: got %q, want %q", r.Reason, ReasonKEVRefresh)
		}
	}
	if !(q.reqs[0].TenantID.Equals(t1) && q.reqs[1].TenantID.Equals(t2)) {
		t.Errorf("tenant ids not preserved: got %s,%s want %s,%s",
			q.reqs[0].TenantID, q.reqs[1].TenantID, t1, t2)
	}
}

func TestKEVRefresh_NilQueue_NoPanic(t *testing.T) {
	c := NewThreatIntelRefreshController(nil, nil, nil, logger.NewNop())
	c.enqueueReclassify(context.Background(), []shared.ID{shared.NewID()})
	// No queue wired → no enqueue, no panic.
}

func TestKEVRefresh_EmptyTenants_NoOp(t *testing.T) {
	q := &captureQueue{}
	c := NewThreatIntelRefreshController(nil, nil, q, logger.NewNop())
	c.enqueueReclassify(context.Background(), nil)
	if len(q.reqs) != 0 {
		t.Fatalf("empty tenant set must not enqueue, got %d", len(q.reqs))
	}
}

func TestKEVRefresh_EnqueueErrorSwallowed(t *testing.T) {
	q := &captureQueue{err: errors.New("queue down")}
	c := NewThreatIntelRefreshController(nil, nil, q, logger.NewNop())
	// Must not panic or propagate — a failed enqueue cannot fail the KEV sync.
	c.enqueueReclassify(context.Background(), []shared.ID{shared.NewID()})
}
