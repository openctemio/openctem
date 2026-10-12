package controller

// Posting CI verdicts to the code host (docs/rfcs/RFC-077-ci-enforced-gate-and-pr-feedback.md).

import (
	"context"
	"time"
)

// CIDecorationInterval is how often queued verdicts are posted.
const CIDecorationInterval = 15 * time.Second

// CIDecorationJob is what the controller runs (cirunapp.DecorationJob).
type CIDecorationJob interface {
	Run(ctx context.Context) (int, error)
}

// CIDecorationController posts queued CI verdicts as check runs and pull
// request comments. Several replicas may run it: runs are claimed with
// SKIP LOCKED.
type CIDecorationController struct {
	job      CIDecorationJob
	interval time.Duration
}

// NewCIDecorationController creates the controller; interval <= 0 uses
// CIDecorationInterval.
func NewCIDecorationController(job CIDecorationJob, interval time.Duration) *CIDecorationController {
	if interval <= 0 {
		interval = CIDecorationInterval
	}
	return &CIDecorationController{job: job, interval: interval}
}

// Name implements Controller.
func (c *CIDecorationController) Name() string { return "ci-decoration" }

// Interval implements Controller.
func (c *CIDecorationController) Interval() time.Duration { return c.interval }

// Reconcile implements Controller.
func (c *CIDecorationController) Reconcile(ctx context.Context) (int, error) {
	return c.job.Run(ctx)
}
