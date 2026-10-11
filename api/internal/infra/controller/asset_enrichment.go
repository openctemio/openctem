package controller

// Automatic asset enrichment (docs/architecture/asset-freshness.md): every
// two minutes, claim the due enrichment requests of each tenant and start
// passive runs of the built-in profiles.

import (
	"context"
	"time"
)

// AssetEnricher processes due enrichment requests (*assetfreshness.Enricher).
type AssetEnricher interface {
	Run(ctx context.Context) (int, error)
}

// AssetEnrichmentController drives the enricher.
type AssetEnrichmentController struct {
	enricher AssetEnricher
	interval time.Duration
}

// NewAssetEnrichmentController creates the controller; interval 0 = 2 min.
func NewAssetEnrichmentController(enricher AssetEnricher, interval time.Duration) *AssetEnrichmentController {
	if interval <= 0 {
		interval = 2 * time.Minute
	}
	return &AssetEnrichmentController{enricher: enricher, interval: interval}
}

// Name returns the controller name.
func (c *AssetEnrichmentController) Name() string { return "asset-enrichment" }

// Interval returns the reconciliation interval.
func (c *AssetEnrichmentController) Interval() time.Duration { return c.interval }

// Exclusive: one replica at a time (claims also skip locked rows).
func (c *AssetEnrichmentController) Exclusive() bool { return true }

// Reconcile processes the due requests.
func (c *AssetEnrichmentController) Reconcile(ctx context.Context) (int, error) {
	return c.enricher.Run(ctx)
}
