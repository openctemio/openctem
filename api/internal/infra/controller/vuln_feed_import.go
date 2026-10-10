package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/internal/app/vulnfeed"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// VulnFeedImportController imports the newest signed vulnerability bundle
// (RFC-066 §5.5) and warns when the corpus goes stale.
type VulnFeedImportController struct {
	importer *vulnfeed.Importer
	logger   *logger.Logger
}

// NewVulnFeedImportController creates the controller.
func NewVulnFeedImportController(im *vulnfeed.Importer, log *logger.Logger) *VulnFeedImportController {
	return &VulnFeedImportController{importer: im, logger: log}
}

// Name returns the controller name.
func (c *VulnFeedImportController) Name() string { return "vuln-feed-import" }

// Interval: hourly; a bundle is published daily.
func (c *VulnFeedImportController) Interval() time.Duration { return time.Hour }

// ReconcileTimeout leaves room for a first snapshot.
func (c *VulnFeedImportController) ReconcileTimeout() time.Duration { return 45 * time.Minute }

// Exclusive: one replica imports.
func (c *VulnFeedImportController) Exclusive() bool { return true }

// Reconcile imports and checks staleness.
func (c *VulnFeedImportController) Reconcile(ctx context.Context) (int, error) {
	res, err := c.importer.Run(ctx)
	if err != nil {
		c.logger.Warn("vulnerability bundle not imported", "error", err)
	}
	if stale, serr := c.importer.CheckStale(ctx); serr == nil && stale && err == nil && !res.Ran {
		c.logger.Warn("vulnerability corpus is stale: no new bundle for more than three days")
	}
	return res.CVEs, nil
}
