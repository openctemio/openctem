package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/internal/app/vulnfeed"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// vulnFeedBudget is how long one run may page through the feed; the
// bootstrap resumes on the next tick where the previous one stopped.
const vulnFeedBudget = 20 * time.Minute

// VulnFeedRefreshController runs the NVD CVE feed (RFC-066): a resumable
// bootstrap, then a daily window of modified CVEs. It does nothing while a
// platform admin has not enabled the "nvd" source.
type VulnFeedRefreshController struct {
	syncer *vulnfeed.Syncer
	logger *logger.Logger
}

// NewVulnFeedRefreshController creates the controller.
func NewVulnFeedRefreshController(syncer *vulnfeed.Syncer, log *logger.Logger) *VulnFeedRefreshController {
	return &VulnFeedRefreshController{syncer: syncer, logger: log}
}

// Name returns the controller name.
func (c *VulnFeedRefreshController) Name() string { return "vuln-feed-refresh" }

// Interval is the tick; the feed itself is synced once a day.
func (c *VulnFeedRefreshController) Interval() time.Duration { return 30 * time.Minute }

// Exclusive: one replica syncs the shared corpus.
func (c *VulnFeedRefreshController) Exclusive() bool { return true }

// Reconcile runs the feed for at most vulnFeedBudget.
func (c *VulnFeedRefreshController) Reconcile(ctx context.Context) (int, error) {
	res, err := c.syncer.Run(ctx, vulnFeedBudget)
	if err != nil {
		c.logger.Warn("nvd feed sync failed", "error", err)
		return res.CVEs, nil
	}
	return res.CVEs, nil
}
