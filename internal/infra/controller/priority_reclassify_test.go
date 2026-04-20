package controller

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// B1 + B2 (Q1/WS-C): unit tests for the reclassify sweep controller.
// Full integration (real queue + real DB + real classifier) lives in
// tests/integration/; here we lock in the dispatcher contract.

// fakeQueue is a thread-safe in-memory ReclassifyQueue for tests.
type fakeQueue struct {
	mu    sync.Mutex
	items []ReclassifyRequest
}

func (q *fakeQueue) Enqueue(_ context.Context, r ReclassifyRequest) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = append(q.items, r)
	return nil
}

func (q *fakeQueue) DequeueBatch(_ context.Context, max int) ([]ReclassifyRequest, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return nil, nil
	}
	n := len(q.items)
	if n > max {
		n = max
	}
	out := make([]ReclassifyRequest, n)
	copy(out, q.items[:n])
	q.items = q.items[n:]
	return out, nil
}

// fakeReclassifier records calls and can simulate errors per-request.
type fakeReclassifier struct {
	mu       sync.Mutex
	calls    []ReclassifyRequest
	errOnIdx int // -1 = no error
	errToRet error
}

func newFakeReclassifier() *fakeReclassifier { return &fakeReclassifier{errOnIdx: -1} }

func (r *fakeReclassifier) ReclassifyForRequest(_ context.Context, req ReclassifyRequest) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := len(r.calls)
	r.calls = append(r.calls, req)
	if idx == r.errOnIdx {
		return 0, r.errToRet
	}
	return 1 + len(req.CVEIDs), nil
}

func (r *fakeReclassifier) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func TestReconcile_DrainsBatch(t *testing.T) {
	q := &fakeQueue{}
	rc := newFakeReclassifier()
	c := NewPriorityReclassifyController(q, rc, &PriorityReclassifyConfig{BatchSize: 10})

	tid := shared.NewID()
	for i := 0; i < 3; i++ {
		_ = q.Enqueue(context.Background(), ReclassifyRequest{
			TenantID: tid, Reason: ReasonEPSSRefresh, CVEIDs: []string{"CVE-1", "CVE-2"},
		})
	}
	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	// Each fake request returns 1 + len(CVEIDs) = 3.
	if n != 9 {
		t.Fatalf("total reexamined = %d, want 9", n)
	}
	if rc.count() != 3 {
		t.Fatalf("reclassifier call count = %d, want 3", rc.count())
	}
	// Queue must now be drained.
	more, _ := q.DequeueBatch(context.Background(), 10)
	if len(more) != 0 {
		t.Fatalf("queue must be drained")
	}
}

func TestReconcile_EmptyQueue_NoOp(t *testing.T) {
	q := &fakeQueue{}
	rc := newFakeReclassifier()
	c := NewPriorityReclassifyController(q, rc, nil)
	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("%v", err)
	}
	if n != 0 {
		t.Fatalf("empty queue should produce 0, got %d", n)
	}
	if rc.count() != 0 {
		t.Fatalf("reclassifier must not be called on empty queue")
	}
}

func TestReconcile_PerRequestErrorDoesNotAbortBatch(t *testing.T) {
	q := &fakeQueue{}
	tid := shared.NewID()
	for i := 0; i < 3; i++ {
		_ = q.Enqueue(context.Background(), ReclassifyRequest{
			TenantID: tid, Reason: ReasonManual,
		})
	}
	rc := newFakeReclassifier()
	rc.errOnIdx = 1 // 2nd request errors
	rc.errToRet = errors.New("boom")
	c := NewPriorityReclassifyController(q, rc, &PriorityReclassifyConfig{BatchSize: 10})

	_, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("batch-level err must be nil, got %v", err)
	}
	if rc.count() != 3 {
		t.Fatalf("all 3 requests must be attempted even after one fails, got %d", rc.count())
	}
}

func TestReconcile_BatchSizeRespected(t *testing.T) {
	q := &fakeQueue{}
	for i := 0; i < 10; i++ {
		_ = q.Enqueue(context.Background(), ReclassifyRequest{
			TenantID: shared.NewID(), Reason: ReasonRuleChanged,
		})
	}
	rc := newFakeReclassifier()
	c := NewPriorityReclassifyController(q, rc, &PriorityReclassifyConfig{BatchSize: 4})

	_, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("%v", err)
	}
	if rc.count() != 4 {
		t.Fatalf("batch size not enforced: %d calls", rc.count())
	}
	// 6 requests should remain queued for the next tick.
	rest, _ := q.DequeueBatch(context.Background(), 10)
	if len(rest) != 6 {
		t.Fatalf("remaining = %d, want 6", len(rest))
	}
}

func TestReconcile_NilDepsSafe(t *testing.T) {
	c := NewPriorityReclassifyController(nil, nil, nil)
	n, err := c.Reconcile(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("nil deps must be a safe no-op (err=%v, n=%d)", err, n)
	}
}

func TestDefaults(t *testing.T) {
	c := NewPriorityReclassifyController(&fakeQueue{}, newFakeReclassifier(), nil)
	if c.Interval() != 5*time.Minute {
		t.Fatalf("default interval = %v", c.Interval())
	}
	if c.Name() != "priority-reclassify" {
		t.Fatalf("name = %q", c.Name())
	}
}

func TestReconcile_ContextCancelledMidBatch(t *testing.T) {
	q := &fakeQueue{}
	tid := shared.NewID()
	for i := 0; i < 5; i++ {
		_ = q.Enqueue(context.Background(), ReclassifyRequest{
			TenantID: tid, Reason: ReasonManual,
		})
	}
	rc := newFakeReclassifier()
	c := NewPriorityReclassifyController(q, rc, &PriorityReclassifyConfig{BatchSize: 10})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	_, _ = c.Reconcile(ctx)
	// The dequeue happens before the loop, so items are drained off
	// the queue even when ctx is dead. But the PER-REQUEST loop must
	// short-circuit. At most the first request may run before the
	// ctx.Err() check.
	if rc.count() > 1 {
		t.Fatalf("cancelled ctx must stop the dispatch loop after ≤1 request, got %d", rc.count())
	}
}
