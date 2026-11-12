package controller

// Resumes retired import sources whose archive or restore batches did not
// finish in the request (docs/architecture/source-retirement.md): a large
// source, or a process that stopped mid-way. Batches are idempotent.

import (
	"context"
	"time"
)

// SourceRetirementInterval is how often unfinished batches are resumed.
const SourceRetirementInterval = 15 * time.Second

// SourceRetirementJob is what the controller runs
// (sourceretireapp.Service.ProcessPending).
type SourceRetirementJob interface {
	ProcessPending(ctx context.Context, limit int) (int, error)
}

// SourceRetirementController runs the pending batches on one replica.
type SourceRetirementController struct {
	job      SourceRetirementJob
	interval time.Duration
}

// NewSourceRetirementController creates the controller; interval <= 0 uses
// SourceRetirementInterval.
func NewSourceRetirementController(job SourceRetirementJob, interval time.Duration) *SourceRetirementController {
	if interval <= 0 {
		interval = SourceRetirementInterval
	}
	return &SourceRetirementController{job: job, interval: interval}
}

// Name implements Controller.
func (c *SourceRetirementController) Name() string { return "source-retirement" }

// Interval implements Controller.
func (c *SourceRetirementController) Interval() time.Duration { return c.interval }

// Exclusive implements Exclusive: one replica runs the batches.
func (c *SourceRetirementController) Exclusive() bool { return true }

// ReconcileTimeout lets one pass run several batches.
func (c *SourceRetirementController) ReconcileTimeout() time.Duration { return 10 * time.Minute }

// Reconcile implements Controller.
func (c *SourceRetirementController) Reconcile(ctx context.Context) (int, error) {
	return c.job.ProcessPending(ctx, 10)
}
