package controller

// Retention of CI runs (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md,
// "Data model").

import (
	"context"
	"time"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
)

// CIRetentionInterval is how often the CI retention job runs. Run tokens live
// 15 minutes; an hourly pass clears their hashes soon enough and keeps the
// purge batches small.
const CIRetentionInterval = time.Hour

// CIRetentionJob is what the controller runs (cirunapp.RetentionJob).
type CIRetentionJob interface {
	Run(ctx context.Context) (cirunapp.RetentionResult, error)
}

// CIRetentionController runs the CI retention job on one replica at a time.
type CIRetentionController struct {
	job      CIRetentionJob
	interval time.Duration
}

// NewCIRetentionController creates the controller; interval <= 0 uses
// CIRetentionInterval.
func NewCIRetentionController(job CIRetentionJob, interval time.Duration) *CIRetentionController {
	if interval <= 0 {
		interval = CIRetentionInterval
	}
	return &CIRetentionController{job: job, interval: interval}
}

// Name implements Controller.
func (c *CIRetentionController) Name() string { return "ci-retention" }

// Interval implements Controller.
func (c *CIRetentionController) Interval() time.Duration { return c.interval }

// Exclusive implements Exclusive: one replica purges.
func (c *CIRetentionController) Exclusive() bool { return true }

// Reconcile implements Controller.
func (c *CIRetentionController) Reconcile(ctx context.Context) (int, error) {
	res, err := c.job.Run(ctx)
	return int(res.TokensCleared + res.FindingsPurged + res.RunsPurged), err
}
