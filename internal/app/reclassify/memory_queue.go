// Package reclassify provides the runtime glue that connects
// priority-change producers (threat-intel refresh, control CRUD, rule
// CRUD) to the PriorityReclassifyController's queue/Reclassifier
// contracts.
//
// The package lives under internal/app so the app-layer wire sites
// (services.go) can see it directly; controller itself imports app for
// unrelated reasons, so placing the adapters in `app` directly would
// introduce a cycle. Keep new code here.
package reclassify

import (
	"context"
	"sync"

	"github.com/openctemio/api/internal/infra/controller"
)

// MemoryQueue is a minimal in-process ReclassifyQueue. It is
// intentionally unbounded (slice-backed) but tolerates burst enqueues
// cheaply — the controller drains at Interval=5m with BatchSize=64, so
// backlog in practice is small. When the API scales beyond a single
// replica, swap this for a Redis or Postgres queue; the interface is
// stable.
//
// Order: FIFO. Dedup: none (controller-side dedup is cheaper — two
// enqueues for the same (tenant,asset) do the same work twice but
// don't produce duplicate priority_changed events thanks to the
// publisher's "no transition = no publish" guard).
type MemoryQueue struct {
	mu    sync.Mutex
	items []controller.ReclassifyRequest
}

// NewMemoryQueue constructs an empty queue.
func NewMemoryQueue() *MemoryQueue {
	return &MemoryQueue{items: make([]controller.ReclassifyRequest, 0, 64)}
}

// Enqueue adds a request. Safe for concurrent use.
func (q *MemoryQueue) Enqueue(_ context.Context, req controller.ReclassifyRequest) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = append(q.items, req)
	return nil
}

// DequeueBatch pops up to max requests. Returns an empty slice (nil
// error) when empty.
func (q *MemoryQueue) DequeueBatch(_ context.Context, max int) ([]controller.ReclassifyRequest, error) {
	if max <= 0 {
		return nil, nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return nil, nil
	}
	n := max
	if n > len(q.items) {
		n = len(q.items)
	}
	out := make([]controller.ReclassifyRequest, n)
	copy(out, q.items[:n])
	// Shift — cheap because batch sizes are small and queue length
	// rarely exceeds a few hundred.
	q.items = append(q.items[:0], q.items[n:]...)
	return out, nil
}

// Len is exposed for observability/dashboards. Safe for concurrent use.
func (q *MemoryQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}
