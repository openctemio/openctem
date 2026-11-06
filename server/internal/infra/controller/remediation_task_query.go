package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// remediationTaskAutoIncluder is the slice of *remediation.TaskService this
// controller drives.
type remediationTaskAutoIncluder interface {
	AutoInclude(ctx context.Context) (int, error)
}

// RemediationTaskQueryController runs the auto-mode queries of remediation
// tasks created from a query (docs/rfcs/RFC-098-remediation-tasks.md, "Tasks
// from a query"): each runs as its owner with the owner's current access
// and adds new matches no other active task holds, up to the task's cap.
type RemediationTaskQueryController struct {
	svc      remediationTaskAutoIncluder
	interval time.Duration
	logger   *logger.Logger
}

// NewRemediationTaskQueryController creates the controller. A non-positive
// interval falls back to 5 minutes (each task itself runs at most every
// remediation.AutoIncludeEvery).
func NewRemediationTaskQueryController(svc remediationTaskAutoIncluder, interval time.Duration, log *logger.Logger) *RemediationTaskQueryController {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &RemediationTaskQueryController{svc: svc, interval: interval, logger: log}
}

// Name returns the controller name.
func (c *RemediationTaskQueryController) Name() string { return "remediation-task-queries" }

// Interval returns how often the pass runs.
func (c *RemediationTaskQueryController) Interval() time.Duration { return c.interval }

// Reconcile runs the due auto-mode queries.
func (c *RemediationTaskQueryController) Reconcile(ctx context.Context) (int, error) {
	n, err := c.svc.AutoInclude(ctx)
	if err != nil {
		return 0, err
	}
	if n > 0 && c.logger != nil {
		c.logger.Debug("query tasks auto include", "added", n)
	}
	return n, nil
}
