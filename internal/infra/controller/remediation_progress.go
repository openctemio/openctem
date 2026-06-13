package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/logger"
)

// campaignProgressReconciler is the narrow slice of the remediation-campaign
// service this controller drives. Satisfied by
// *exposure.RemediationCampaignService.
type campaignProgressReconciler interface {
	ReconcileProgress(ctx context.Context) (int, error)
}

// RemediationProgressController periodically refreshes finding counts for every
// non-terminal remediation campaign and auto-completes any whose findings are
// all resolved. Without it, campaign progress would only update when a campaign
// is fetched individually — list views and auto-complete would lag reality.
type RemediationProgressController struct {
	svc      campaignProgressReconciler
	interval time.Duration
	logger   *logger.Logger
}

// NewRemediationProgressController creates the controller. A non-positive
// interval falls back to 30 minutes.
func NewRemediationProgressController(svc campaignProgressReconciler, interval time.Duration, log *logger.Logger) *RemediationProgressController {
	if interval <= 0 {
		interval = 30 * time.Minute
	}
	return &RemediationProgressController{svc: svc, interval: interval, logger: log}
}

// Name returns the controller name.
func (c *RemediationProgressController) Name() string { return "remediation-progress" }

// Interval returns how often the reconcile runs.
func (c *RemediationProgressController) Interval() time.Duration { return c.interval }

// Reconcile refreshes progress for all non-terminal campaigns.
func (c *RemediationProgressController) Reconcile(ctx context.Context) (int, error) {
	updated, err := c.svc.ReconcileProgress(ctx)
	if err != nil {
		return 0, err
	}
	if updated > 0 && c.logger != nil {
		c.logger.Info("remediation campaign progress reconciled", "updated", updated)
	}
	return updated, nil
}
