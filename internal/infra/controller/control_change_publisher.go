package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// (invariant B2): compensating-control change → reclassification.
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

// PublishChange enqueues a control-change reclassify request. Errors are logged
// but NOT returned — a failed enqueue must not roll back the control write that
// triggered it.
func (p *ControlChangePublisher) PublishChange(
	ctx context.Context,
	tenantID shared.ID,
	assetIDs []shared.ID,
	reason string,
) {
	p.PublishAssetReclassify(ctx, tenantID, assetIDs, ReasonControlChange, reason)
}

// PublishAssetReclassify enqueues an asset-scoped reclassify request under an
// explicit reason kind. Generalizes PublishChange (which is always
// ReasonControlChange) so other producers — e.g. AI triage completion
// (ReasonAITriage) — drive the same asset-scoped sweep. Errors are logged, never
// returned: a failed enqueue must not roll back the write that triggered it.
func (p *ControlChangePublisher) PublishAssetReclassify(
	ctx context.Context,
	tenantID shared.ID,
	assetIDs []shared.ID,
	kind ReclassifyReasonKind,
	reason string,
) {
	if p.queue == nil || len(assetIDs) == 0 {
		return
	}
	req := ReclassifyRequest{
		TenantID:  tenantID,
		Reason:    kind,
		AssetIDs:  assetIDs,
		EnqueueAt: time.Now().UTC(),
	}
	if err := p.queue.Enqueue(ctx, req); err != nil {
		p.logger.Warn("enqueue asset-scoped reclassify failed",
			"tenant_id", tenantID.String(),
			"asset_count", len(assetIDs),
			"kind", string(kind),
			"reason", reason,
			"error", err,
		)
	}
}

// PublishTenantChange enqueues a WHOLE-TENANT reclassify sweep (no asset scope),
// used when a change affects every finding in the tenant rather than a known set
// of assets — e.g. a priority override rule was created, updated, or deleted.
// The reclassifier treats an empty AssetIDs as "page the tenant's open findings
// and reclassify each". Errors are logged, never returned — a failed enqueue
// must not roll back the mutation that triggered it.
func (p *ControlChangePublisher) PublishTenantChange(
	ctx context.Context,
	tenantID shared.ID,
	kind ReclassifyReasonKind,
	reason string,
) {
	if p.queue == nil {
		return
	}
	req := ReclassifyRequest{
		TenantID:  tenantID,
		Reason:    kind,
		EnqueueAt: time.Now().UTC(),
	}
	if err := p.queue.Enqueue(ctx, req); err != nil {
		p.logger.Warn("enqueue whole-tenant reclassify failed",
			"tenant_id", tenantID.String(),
			"reason", reason,
			"kind", string(kind),
			"error", err,
		)
	}
}
