package main

import (
	"context"

	"github.com/openctemio/api/internal/infra/controller"
	"github.com/openctemio/api/pkg/domain/shared"
)

// aiTriageReclassifyEnqueuer adapts the ControlChangePublisher to the AI-triage
// service's PriorityReclassifyEnqueuer port: when a triage completes with a
// high-confidence false-positive verdict, it enqueues an asset-scoped reclassify
// (reason ai_triage) so the classifier re-derives — and de-escalates — the
// finding's priority. Errors are swallowed by the publisher (a failed enqueue
// must not fail the triage; the verdict still applies on the next sweep).
type aiTriageReclassifyEnqueuer struct {
	pub *controller.ControlChangePublisher
}

// EnqueueForAsset enqueues an ai_triage-scoped reclassify for a single asset.
func (a aiTriageReclassifyEnqueuer) EnqueueForAsset(ctx context.Context, tenantID, assetID shared.ID) {
	if a.pub == nil || assetID.IsZero() {
		return
	}
	a.pub.PublishAssetReclassify(ctx, tenantID, []shared.ID{assetID}, controller.ReasonAITriage, "ai_triage_completed")
}
