package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/pipeline"
	"github.com/openctemio/api/pkg/logger"
)

// ScanTimeoutControllerConfig configures the ScanTimeoutController.
type ScanTimeoutControllerConfig struct {
	// Interval is how often to check for timed-out runs.
	// Default: 60 seconds.
	Interval time.Duration

	// Logger for logging.
	Logger *logger.Logger
}

// ScanTimeoutController periodically marks pipeline_runs as timed out when they
// exceed their scan's configured timeout_seconds.
//
// This complements JobRecoveryController (which marks stuck commands) by
// enforcing per-scan timeouts. A scan can specify its own timeout_seconds
// (default 1h, max 24h), and runs that exceed that are forcefully marked
// as timeout with an appropriate error message.
type ScanTimeoutController struct {
	runRepo pipeline.RunRepository
	config  *ScanTimeoutControllerConfig
	logger  *logger.Logger
}

// NewScanTimeoutController creates a new ScanTimeoutController.
func NewScanTimeoutController(
	runRepo pipeline.RunRepository,
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

// Reconcile marks expired runs as timed out.
func (c *ScanTimeoutController) Reconcile(ctx context.Context) (int, error) {
	count, err := c.runRepo.MarkTimedOutRuns(ctx)
	if err != nil {
		c.logger.Error("failed to mark timed out scan runs", "error", err)
		return 0, err
	}

	if count > 0 {
		c.logger.Info("marked scan runs as timeout", "count", count)
	}

	return int(count), nil
}
