package controller

// CI alerts and stale sources (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md §10.6).

import (
	"context"
	"time"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
)

// CIAlertsInterval is how often the CI alert job runs. Pipelines go stale
// over days, so a quarter of an hour is precise enough and cheap.
const CIAlertsInterval = 15 * time.Minute

// CIAlertJob is what the controller runs (cirunapp.AlertJob).
type CIAlertJob interface {
	Run(ctx context.Context) (cirunapp.AlertRunResult, error)
}

// CIAlertsController runs the CI alert job on one replica at a time: alerts
// for missed schedules, lost coverage, failing default branches and outdated
// runners (each sent once while its condition holds), and the stale-source
// finding update.
type CIAlertsController struct {
	job      CIAlertJob
	interval time.Duration
}

// NewCIAlertsController creates the controller; interval <= 0 uses
// CIAlertsInterval.
func NewCIAlertsController(job CIAlertJob, interval time.Duration) *CIAlertsController {
	if interval <= 0 {
		interval = CIAlertsInterval
	}
	return &CIAlertsController{job: job, interval: interval}
}

// Name implements Controller.
func (c *CIAlertsController) Name() string { return "ci-alerts" }

// Interval implements Controller.
func (c *CIAlertsController) Interval() time.Duration { return c.interval }

// Exclusive implements Exclusive: one replica sends the alerts.
func (c *CIAlertsController) Exclusive() bool { return true }

// Reconcile implements Controller.
func (c *CIAlertsController) Reconcile(ctx context.Context) (int, error) {
	res, err := c.job.Run(ctx)
	return res.Fired + res.Cleared + res.StaleFindings, err
}
