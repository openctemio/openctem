package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/internal/app/ingest"
)

// AssetIdentityBackfillController derives asset identifiers for tenants whose
// inventory predates the asset identity model, and raises duplicate reviews
// for what it finds (a shared strong identifier, a host a scanner reported
// under two names). It never merges. A tenant is done once per backfill
// version, so later runs only pick up new tenants; the work per tick is one
// small query when nothing is pending.
type AssetIdentityBackfillController struct {
	backfill *ingest.IdentityBackfill
}

// NewAssetIdentityBackfillController creates the controller.
func NewAssetIdentityBackfillController(b *ingest.IdentityBackfill) *AssetIdentityBackfillController {
	return &AssetIdentityBackfillController{backfill: b}
}

// Name returns the controller name.
func (c *AssetIdentityBackfillController) Name() string { return "asset-identity-backfill" }

// Interval returns how often pending tenants are checked.
func (c *AssetIdentityBackfillController) Interval() time.Duration { return time.Hour }

// ReconcileTimeout allows a large inventory to finish in one run.
func (c *AssetIdentityBackfillController) ReconcileTimeout() time.Duration { return 30 * time.Minute }

// Reconcile backfills every pending tenant.
func (c *AssetIdentityBackfillController) Reconcile(ctx context.Context) (int, error) {
	return c.backfill.Run(ctx)
}
