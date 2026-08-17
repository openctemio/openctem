package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

// errOnTenantQueue enqueues normally except for one tenant, for which it
// returns an error — exercising the best-effort "one failure doesn't stop the
// rest" contract.
type errOnTenantQueue struct {
	fakeQueue
	failFor shared.ID
}

func (q *errOnTenantQueue) Enqueue(ctx context.Context, r ReclassifyRequest) error {
	if r.TenantID == q.failFor {
		return errors.New("boom")
	}
	return q.fakeQueue.Enqueue(ctx, r)
}

func TestPriorityReclassifySweep_EnqueuesOnePerActiveTenant(t *testing.T) {
	t1, t2, t3 := shared.NewID(), shared.NewID(), shared.NewID()
	q := &fakeQueue{}
	repo := &fakeTenantLister{ids: []shared.ID{t1, t2, t3}}
	c := NewPriorityReclassifySweepController(q, repo, nil)

	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if n != 3 {
		t.Fatalf("enqueued = %d, want 3", n)
	}

	reqs, _ := q.DequeueBatch(context.Background(), 100)
	if len(reqs) != 3 {
		t.Fatalf("queued %d requests, want 3", len(reqs))
	}
	seen := map[shared.ID]bool{}
	for _, r := range reqs {
		if r.Reason != ReasonPeriodicSweep {
			t.Fatalf("reason = %q, want %q", r.Reason, ReasonPeriodicSweep)
		}
		if len(r.AssetIDs) != 0 {
			t.Fatalf("whole-tenant request must have no AssetIDs, got %d", len(r.AssetIDs))
		}
		seen[r.TenantID] = true
	}
	for _, tid := range []shared.ID{t1, t2, t3} {
		if !seen[tid] {
			t.Fatalf("missing enqueue for tenant %s", tid)
		}
	}
}

func TestPriorityReclassifySweep_NilQueueIsNoOp(t *testing.T) {
	repo := &fakeTenantLister{ids: []shared.ID{shared.NewID()}}
	c := NewPriorityReclassifySweepController(nil, repo, nil)

	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("nil-queue reconcile must not error: %v", err)
	}
	if n != 0 {
		t.Fatalf("nil-queue reconcile enqueued %d, want 0", n)
	}
}

func TestPriorityReclassifySweep_OneEnqueueErrorDoesNotStopRest(t *testing.T) {
	t1, t2, t3 := shared.NewID(), shared.NewID(), shared.NewID()
	q := &errOnTenantQueue{failFor: t2}
	repo := &fakeTenantLister{ids: []shared.ID{t1, t2, t3}}
	c := NewPriorityReclassifySweepController(q, repo, nil)

	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile must not fail on a per-tenant enqueue error: %v", err)
	}
	// t1 and t3 succeed; t2 errored.
	if n != 2 {
		t.Fatalf("enqueued = %d, want 2 (t2 failed)", n)
	}
	reqs, _ := q.DequeueBatch(context.Background(), 100)
	if len(reqs) != 2 {
		t.Fatalf("queued %d requests, want 2", len(reqs))
	}
	for _, r := range reqs {
		if r.TenantID == t2 {
			t.Fatal("t2 must not have been enqueued")
		}
	}
}

func TestPriorityReclassifySweep_TenantListErrorPropagates(t *testing.T) {
	q := &fakeQueue{}
	repo := &fakeTenantLister{err: errors.New("db down")}
	c := NewPriorityReclassifySweepController(q, repo, nil)

	if _, err := c.Reconcile(context.Background()); err == nil {
		t.Fatal("tenant list error must propagate")
	}
}

func TestPriorityReclassifySweep_Meta(t *testing.T) {
	c := NewPriorityReclassifySweepController(&fakeQueue{}, &fakeTenantLister{}, nil)
	if c.Name() != "priority-reclassify-sweep" {
		t.Fatalf("name: %q", c.Name())
	}
	if c.Interval() <= 0 {
		t.Fatal("interval should default to a positive duration")
	}
}
