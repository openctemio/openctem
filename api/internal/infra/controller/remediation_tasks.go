package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// remediationTaskReconciler is the slice of *remediation.TaskService this
// controller drives.
type remediationTaskReconciler interface {
	Reconcile(ctx context.Context) (int, error)
}

// RemediationTaskController recomputes the derived state, deadline and
// counters of remediation tasks whose member findings changed since their
// last recompute (docs/rfcs/RFC-098-remediation-tasks.md).
type RemediationTaskController struct {
	svc      remediationTaskReconciler
	interval time.Duration
	logger   *logger.Logger
}

// NewRemediationTaskController creates the controller. A non-positive
// interval falls back to 2 minutes.
func NewRemediationTaskController(svc remediationTaskReconciler, interval time.Duration, log *logger.Logger) *RemediationTaskController {
	if interval <= 0 {
		interval = 2 * time.Minute
	}
	return &RemediationTaskController{svc: svc, interval: interval, logger: log}
}

// Name returns the controller name.
func (c *RemediationTaskController) Name() string { return "remediation-tasks" }

// Interval returns how often the reconcile runs.
func (c *RemediationTaskController) Interval() time.Duration { return c.interval }

// Reconcile recomputes the stale tasks.
func (c *RemediationTaskController) Reconcile(ctx context.Context) (int, error) {
	n, err := c.svc.Reconcile(ctx)
	if err != nil {
		return 0, err
	}
	if n > 0 && c.logger != nil {
		c.logger.Debug("remediation tasks recomputed", "tasks", n)
	}
	return n, nil
}
