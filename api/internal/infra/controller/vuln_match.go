package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/internal/app/vulnmatch"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// vulnMatchBudget is how long one pass may run; work left over continues
// on the next tick.
const vulnMatchBudget = 4 * time.Minute

// VulnMatchController runs inventory vulnerability matching (RFC-066): feed
// changes, pending versions, the daily sweep and queued organizations.
type VulnMatchController struct {
	svc    *vulnmatch.Service
	logger *logger.Logger
}

// NewVulnMatchController creates the controller.
func NewVulnMatchController(svc *vulnmatch.Service, log *logger.Logger) *VulnMatchController {
	return &VulnMatchController{svc: svc, logger: log}
}

// Name returns the controller name.
func (c *VulnMatchController) Name() string { return "vuln-match" }

// Interval: every minute, so new software and new CVEs reach findings fast.
func (c *VulnMatchController) Interval() time.Duration { return time.Minute }

// ReconcileTimeout leaves room for the budget.
func (c *VulnMatchController) ReconcileTimeout() time.Duration { return vulnMatchBudget + time.Minute }

// Exclusive: one replica matches.
func (c *VulnMatchController) Exclusive() bool { return true }

// Reconcile runs one pass.
func (c *VulnMatchController) Reconcile(ctx context.Context) (int, error) {
	st, err := c.svc.Run(ctx, vulnMatchBudget)
	if st.VersionsEvaluated > 0 || st.Tenants > 0 {
		c.logger.Info("vulnerability matching", "versions_reset", st.VersionsReset,
			"versions_evaluated", st.VersionsEvaluated, "versions_changed", st.VersionsChanged,
			"tenants", st.Tenants, "created", st.Created, "reopened", st.Reopened, "closed", st.Closed)
	}
	if err != nil {
		c.logger.Warn("vulnerability matching failed", "error", err)
	}
	return st.Created + st.Closed + st.Reopened, nil
}
