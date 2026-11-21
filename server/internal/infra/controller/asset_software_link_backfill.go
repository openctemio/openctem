package controller

import (
	"context"
	"time"

	assettechapp "github.com/openctemio/openctem/server/internal/app/assettech"
)

// AssetSoftwareLinkBackfillController links the stored technologies of
// curated public products whose version is hidden to the software
// inventory, so the matcher lists those assets as possibly affected
// (docs/architecture/vulnerability-matching.md, "Version hidden"). A tenant
// is done once per job version and resumes from its saved position when a
// run is cut short; the work per tick is one small query when nothing is
// pending.
type AssetSoftwareLinkBackfillController struct {
	backfill *assettechapp.SoftwareLinkBackfill
}

// NewAssetSoftwareLinkBackfillController creates the controller.
func NewAssetSoftwareLinkBackfillController(b *assettechapp.SoftwareLinkBackfill) *AssetSoftwareLinkBackfillController {
	return &AssetSoftwareLinkBackfillController{backfill: b}
}

// Name returns the controller name.
func (c *AssetSoftwareLinkBackfillController) Name() string { return "asset-software-link-backfill" }

// Interval returns how often pending tenants are checked.
func (c *AssetSoftwareLinkBackfillController) Interval() time.Duration { return time.Hour }

// ReconcileTimeout bounds one run; a tenant not finished continues next run.
func (c *AssetSoftwareLinkBackfillController) ReconcileTimeout() time.Duration {
	return 20 * time.Minute
}

// Reconcile links pending tenants until the run's time is up.
func (c *AssetSoftwareLinkBackfillController) Reconcile(ctx context.Context) (int, error) {
	return c.backfill.Run(ctx)
}
