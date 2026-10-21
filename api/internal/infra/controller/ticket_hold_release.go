package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// TicketHoldReleaser re-checks held findings against their integration's
// ticket create policy and files the ones that now pass
// (docs/architecture/ticket-create-policy.md).
type TicketHoldReleaser interface {
	ReleaseDue(ctx context.Context, limit int) (int, error)
}

// TicketCounterPurger deletes old daily counters.
type TicketCounterPurger interface {
	PurgeDaily(ctx context.Context, olderThan time.Duration) (int64, error)
}

// TicketHoldReleaseController runs the release every Interval: a finding
// that rose above the policy (severity, priority class, KEV), a policy that
// was loosened, a new day for capped holds, or a failed create due for a
// retry. Each run handles at most BatchSize holds, highest severity first;
// the daily cap bounds what one run can create.
type TicketHoldReleaseController struct {
	releaser  TicketHoldReleaser
	purger    TicketCounterPurger
	interval  time.Duration
	batchSize int
	logger    *logger.Logger
}

// NewTicketHoldReleaseController builds the controller (interval 2 minutes,
// batch 200 when zero).
func NewTicketHoldReleaseController(releaser TicketHoldReleaser, purger TicketCounterPurger, interval time.Duration, batchSize int, log *logger.Logger) *TicketHoldReleaseController {
	if interval <= 0 {
		interval = 2 * time.Minute
	}
	if batchSize <= 0 {
		batchSize = 200
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &TicketHoldReleaseController{releaser: releaser, purger: purger, interval: interval, batchSize: batchSize, logger: log}
}

// Name implements Controller.
func (c *TicketHoldReleaseController) Name() string { return "ticket-hold-release" }

// Interval implements Controller.
func (c *TicketHoldReleaseController) Interval() time.Duration { return c.interval }

// Exclusive: one API replica at a time (controller lease). Two replicas
// listing the same due holds would both file the issue: the tracker-side
// marker lookup is a search, which does not see an issue created a moment
// earlier.
func (c *TicketHoldReleaseController) Exclusive() bool { return true }

// Reconcile implements Controller.
func (c *TicketHoldReleaseController) Reconcile(ctx context.Context) (int, error) {
	if c.purger != nil {
		if _, err := c.purger.PurgeDaily(ctx, 7*24*time.Hour); err != nil {
			c.logger.Warn("purge ticket counters", "error", err)
		}
	}
	n, err := c.releaser.ReleaseDue(ctx, c.batchSize)
	if n > 0 {
		c.logger.Info("released held findings to the tracker", "created", n)
	}
	return n, err
}
