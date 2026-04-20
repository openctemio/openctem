package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// Q2/WS-C (invariant B2): compensating-control change → reclassification.
//
// Placed in the controller package (rather than app) because the queue
// lives here and the app-layer import would otherwise cycle. The
// service is called from app-layer writers via dependency injection.

// ControlChangePublisher enqueues reclassify requests scoped to the
// assets a changed control protects.
type ControlChangePublisher struct {
	queue  ReclassifyQueue
	logger *logger.Logger
}

// NewControlChangePublisher wires the queue.
func NewControlChangePublisher(q ReclassifyQueue, log *logger.Logger) *ControlChangePublisher {
	if log == nil {
		log = logger.NewNop()
	}
	return &ControlChangePublisher{queue: q, logger: log.With("service", "control-change")}
}

// PublishChange enqueues a reclassify request. Errors are logged but
// NOT returned — a failed enqueue must not roll back the control
// write that triggered it.
func (p *ControlChangePublisher) PublishChange(
	ctx context.Context,
	tenantID shared.ID,
	assetIDs []shared.ID,
	reason string,
) {
	if p.queue == nil || len(assetIDs) == 0 {
		return
	}
	req := ReclassifyRequest{
		TenantID:  tenantID,
		Reason:    ReasonControlChange,
		AssetIDs:  assetIDs,
		EnqueueAt: time.Now().UTC(),
	}
	if err := p.queue.Enqueue(ctx, req); err != nil {
		p.logger.Warn("enqueue reclassify after control change failed",
			"tenant_id", tenantID.String(),
			"asset_count", len(assetIDs),
			"reason", reason,
			"error", err,
		)
	}
}
