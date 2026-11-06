package controller

import (
	"context"
	"time"

	assettechapp "github.com/openctemio/openctem/api/internal/app/assettech"
)

// AssetTechnologyBackfillController fills the detected technologies of
// assets that predate them and removes the component links ingest no
// longer creates (docs/rfcs/RFC-112-asset-technologies.md). A tenant is
// done once per backfill version, so later runs only pick up new tenants;
// the work per tick is one small query when nothing is pending.
type AssetTechnologyBackfillController struct {
	backfill *assettechapp.Backfill
}

// NewAssetTechnologyBackfillController creates the controller.
func NewAssetTechnologyBackfillController(b *assettechapp.Backfill) *AssetTechnologyBackfillController {
	return &AssetTechnologyBackfillController{backfill: b}
}

// Name returns the controller name.
func (c *AssetTechnologyBackfillController) Name() string { return "asset-technology-backfill" }

// Interval returns how often pending tenants are checked.
func (c *AssetTechnologyBackfillController) Interval() time.Duration { return time.Hour }

// ReconcileTimeout allows a large inventory to finish in one run.
func (c *AssetTechnologyBackfillController) ReconcileTimeout() time.Duration { return 30 * time.Minute }

// Reconcile backfills every pending tenant.
func (c *AssetTechnologyBackfillController) Reconcile(ctx context.Context) (int, error) {
	return c.backfill.Run(ctx)
}
