package controller

import (
	"context"
	"time"

	workflowdom "github.com/openctemio/openctem/api/pkg/domain/workflow"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AutomationRunReaper ends automation runs nothing will finish. Runs execute
// in memory: a restart (or a crash) leaves them pending or running forever,
// and they hold the automation's active-run cap. A run is executed within
// minutes (5 at most, after up to 30 waiting for a slot), so one older than
// the cutoff is not coming back. It runs on start and every 15 minutes.
type AutomationRunReaper struct {
	repo   workflowdom.StaleRunReaper
	maxAge time.Duration
	logger *logger.Logger
	now    func() time.Time
}

// automationRunMaxAge is how old a pending or running run is before it is
// ended: well past the longest wait plus execution.
const automationRunMaxAge = time.Hour

// NewAutomationRunReaper builds the reaper; maxAge <= 0 means one hour.
func NewAutomationRunReaper(repo workflowdom.StaleRunReaper, maxAge time.Duration, log *logger.Logger) *AutomationRunReaper {
	if maxAge <= 0 {
		maxAge = automationRunMaxAge
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &AutomationRunReaper{repo: repo, maxAge: maxAge, logger: log, now: time.Now}
}

// Name returns the controller name.
func (c *AutomationRunReaper) Name() string { return "automation-run-reaper" }

// Interval returns the reconciliation interval.
func (c *AutomationRunReaper) Interval() time.Duration { return 15 * time.Minute }

// Reconcile fails the stale runs and their open steps.
func (c *AutomationRunReaper) Reconcile(ctx context.Context) (int, error) {
	n, err := c.repo.FailStaleRuns(ctx, c.now().Add(-c.maxAge),
		"interrupted: the run did not finish (the server restarted or the run was lost)")
	if err != nil {
		c.logger.Error("failed to end stale automation runs", "error", err)
		return 0, err
	}
	if n > 0 {
		c.logger.Warn("ended stale automation runs", "count", n)
	}
	return int(n), nil
}

// Exclusive: one API replica at a time (controller lease).
func (c *AutomationRunReaper) Exclusive() bool { return true }
