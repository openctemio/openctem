package controller

import (
	"context"
	"time"

	automationdom "github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AutomationRunExpirer deletes finished automation runs past their retention.
type AutomationRunExpirer interface {
	DeleteExpiredRuns(ctx context.Context, simulateBefore, liveBefore time.Time, limit int) (int64, error)
}

// AutomationRunRetention deletes automation runs past their retention:
// simulate runs after 30 days, live runs after 180 days (their steps and
// deliveries go with them). The console states the date on each run.
type AutomationRunRetention struct {
	repo   AutomationRunExpirer
	logger *logger.Logger
	now    func() time.Time
}

// automationRetentionBatch bounds one delete so a backlog never holds a long lock.
const automationRetentionBatch = 5000

// NewAutomationRunRetention builds the retention controller.
func NewAutomationRunRetention(repo AutomationRunExpirer, log *logger.Logger) *AutomationRunRetention {
	if log == nil {
		log = logger.NewNop()
	}
	return &AutomationRunRetention{repo: repo, logger: log, now: time.Now}
}

// Name returns the controller name.
func (c *AutomationRunRetention) Name() string { return "automation-run-retention" }

// Interval returns the reconciliation interval.
func (c *AutomationRunRetention) Interval() time.Duration { return 6 * time.Hour }

// Reconcile deletes expired runs in batches until none is left.
func (c *AutomationRunRetention) Reconcile(ctx context.Context) (int, error) {
	now := c.now()
	total := 0
	for {
		n, err := c.repo.DeleteExpiredRuns(ctx, now.Add(-automationdom.SimulateRunRetention),
			now.Add(-automationdom.LiveRunRetention), automationRetentionBatch)
		if err != nil {
			c.logger.Error("failed to delete expired automation runs", "error", err)
			return total, err
		}
		total += int(n)
		if n < automationRetentionBatch || ctx.Err() != nil {
			break
		}
	}
	if total > 0 {
		c.logger.Info("deleted expired automation runs", "count", total)
	}
	return total, nil
}

// Exclusive: one API replica at a time (controller lease).
func (c *AutomationRunRetention) Exclusive() bool { return true }
