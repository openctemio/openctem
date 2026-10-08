package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"

	"github.com/openctemio/openctem/api/internal/metrics"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// ScanTimeoutControllerConfig configures the ScanTimeoutController.
type ScanTimeoutControllerConfig struct {
	// Interval is how often to check for timed-out runs.
	// Default: 60 seconds.
	Interval time.Duration

	// Logger for logging.
	Logger *logger.Logger
}

// ScanTimeoutController periodically marks scan_runs as timed out when they
// exceed their scan's configured timeout_seconds.
//
// This complements JobRecoveryController (which marks stuck commands) by
// enforcing per-scan timeouts. A scan can specify its own timeout_seconds
// (default 1h, max 24h), and runs that exceed that are forcefully marked
// as timeout with an appropriate error message.
type ScanTimeoutController struct {
	runRepo scanrun.RunRepository
	config  *ScanTimeoutControllerConfig
	logger  *logger.Logger
	// onReaped hears about every run a pass ended, so a timed-out or
	// unclaimed run fires the run-finished event too (nil: nobody listens).
	onReaped func(ctx context.Context, runs []scanrun.ReapedRun)
}

// SetReapedRunListener tells fn about every run a pass ends.
func (c *ScanTimeoutController) SetReapedRunListener(fn func(ctx context.Context, runs []scanrun.ReapedRun)) {
	c.onReaped = fn
}

// NewScanTimeoutController creates a new ScanTimeoutController.
func NewScanTimeoutController(
	runRepo scanrun.RunRepository,
	config *ScanTimeoutControllerConfig,
) *ScanTimeoutController {
	if config == nil {
		config = &ScanTimeoutControllerConfig{}
	}
	if config.Interval == 0 {
		config.Interval = 60 * time.Second
	}
	if config.Logger == nil {
		config.Logger = logger.NewNop()
	}

	return &ScanTimeoutController{
		runRepo: runRepo,
		config:  config,
		logger:  config.Logger,
	}
}

// Name returns the controller name.
func (c *ScanTimeoutController) Name() string {
	return "scan-timeout"
}

// Interval returns the reconciliation interval.
func (c *ScanTimeoutController) Interval() time.Duration {
	return c.config.Interval
}

// Defaults for ending a run no sensor ever picked up (D8).
const (
	UnclaimedScheduledRunAfter   = 4 * time.Hour
	UnclaimedInteractiveRunAfter = time.Hour
)

// Reconcile ends runs no sensor picked up, then marks expired runs as timed out.
func (c *ScanTimeoutController) Reconcile(ctx context.Context) (int, error) {
	// First, so an unclaimed run ends with the reason instead of as a
	// generic timeout (and is not retried: no sensor is a permanent class).
	if rep, ok := c.runRepo.(scanrun.ReapedRunReporter); ok && c.onReaped != nil {
		return c.reconcileReporting(ctx, rep)
	}
	aborted := int64(0)
	if a, ok := c.runRepo.(scanrun.UnclaimedRunAborter); ok {
		n, err := a.AbortUnclaimedRuns(ctx, UnclaimedScheduledRunAfter, UnclaimedInteractiveRunAfter)
		if err != nil {
			c.logger.Error("failed to abort unclaimed scan runs", "error", err)
		} else if n > 0 {
			c.logger.Info("ended scan runs no sensor picked up", "count", n)
			metrics.ScanRunsReapedTotal.WithLabelValues("unclaimed").Add(float64(n))
			aborted = n
		}
	}

	count, err := c.runRepo.MarkTimedOutRuns(ctx)
	if err != nil {
		c.logger.Error("failed to mark timed out scan runs", "error", err)
		return 0, err
	}

	if count > 0 {
		c.logger.Info("ended scan runs past their deadline (partial when some work finished, else timeout)", "count", count)
		metrics.ScanRunsReapedTotal.WithLabelValues("deadline").Add(float64(count))
	}

	return int(count + aborted), nil
}

// reconcileReporting is Reconcile with a repository that reports the runs it
// ends, each of which is handed to the listener.
func (c *ScanTimeoutController) reconcileReporting(ctx context.Context, rep scanrun.ReapedRunReporter) (int, error) {
	unclaimed, err := rep.AbortUnclaimedRunsReporting(ctx, UnclaimedScheduledRunAfter, UnclaimedInteractiveRunAfter)
	if err != nil {
		c.logger.Error("failed to abort unclaimed scan runs", "error", err)
	} else if len(unclaimed) > 0 {
		c.logger.Info("ended scan runs no sensor picked up", "count", len(unclaimed))
		metrics.ScanRunsReapedTotal.WithLabelValues("unclaimed").Add(float64(len(unclaimed)))
		c.onReaped(ctx, unclaimed)
	}
	timedOut, err := rep.MarkTimedOutRunsReporting(ctx)
	if err != nil {
		c.logger.Error("failed to mark timed out scan runs", "error", err)
		return len(unclaimed), err
	}
	if len(timedOut) > 0 {
		c.logger.Info("ended scan runs past their deadline (partial when some work finished, else timeout)", "count", len(timedOut))
		metrics.ScanRunsReapedTotal.WithLabelValues("deadline").Add(float64(len(timedOut)))
		c.onReaped(ctx, timedOut)
	}
	return len(unclaimed) + len(timedOut), nil
}
