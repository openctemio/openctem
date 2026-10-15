package reclassify

import (
	"context"

	"github.com/openctemio/openctem/api/internal/infra/controller"
	"github.com/openctemio/openctem/api/pkg/domain/scoring"
)

// Queue adapts the durable finding-priority queue to the producers'
// controller.ReclassifyQueue.
type Queue struct {
	q scoring.PriorityQueue
}

// NewQueue wraps q.
func NewQueue(q scoring.PriorityQueue) *Queue { return &Queue{q: q} }

var _ controller.ReclassifyQueue = (*Queue)(nil)

// Enqueue queues the request's assets, or every asset of the tenant with an
// open finding when it names none.
func (q *Queue) Enqueue(ctx context.Context, req controller.ReclassifyRequest) error {
	if q == nil || q.q == nil {
		return nil
	}
	if len(req.AssetIDs) == 0 {
		return q.q.EnqueueTenant(ctx, req.TenantID, string(req.Reason))
	}
	return q.q.EnqueueAssets(ctx, req.TenantID, req.AssetIDs, string(req.Reason))
}
