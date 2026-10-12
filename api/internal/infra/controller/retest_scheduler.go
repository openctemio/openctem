package controller

import (
	"context"
	"time"

	retestapp "github.com/openctemio/openctem/api/internal/app/retest"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// RetestTicker is the retest service's scheduler pass (RFC-039).
type RetestTicker interface {
	Tick(ctx context.Context, auto retestapp.AutoStore) (int, error)
}

// RetestScheduler settles stale retests and serves due auto-retest ticks
// (RFC-039 §6.3). Every API replica runs it: each tenant tick is claimed by
// compare-and-set before any work is queued, a pending retest is unique per
// finding, and settling is a compare-and-set on the retest row, so replicas
// never double-fire.
type RetestScheduler struct {
	ticker   RetestTicker
	auto     retestapp.AutoStore
	interval time.Duration
	logger   *logger.Logger
}

// NewRetestScheduler builds the controller. auto may be nil (sweep only).
func NewRetestScheduler(ticker RetestTicker, auto retestapp.AutoStore, interval time.Duration, log *logger.Logger) *RetestScheduler {
	if interval <= 0 {
		interval = time.Minute
	}
	return &RetestScheduler{ticker: ticker, auto: auto, interval: interval, logger: log.With("controller", "retest-scheduler")}
}

// Name implements Controller.
func (c *RetestScheduler) Name() string { return "retest-scheduler" }

// Interval implements Controller.
func (c *RetestScheduler) Interval() time.Duration { return c.interval }

// Reconcile implements Controller.
func (c *RetestScheduler) Reconcile(ctx context.Context) (int, error) {
	return c.ticker.Tick(ctx, c.auto)
}
