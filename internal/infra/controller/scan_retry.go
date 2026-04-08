package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/pipeline"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// RetryDispatcher is the dependency the ScanRetryController uses to actually
// re-trigger a failed scan run. The scan service implements this.
type RetryDispatcher interface {
	RetryScanRun(ctx context.Context, tenantID, scanID shared.ID, retryAttempt int) error
}

// ScanRetryControllerConfig configures the ScanRetryController.
type ScanRetryControllerConfig struct {
	// Interval is how often to check for retry candidates.
	// Default: 60 seconds.
	Interval time.Duration

	// BatchSize is the maximum candidates processed per cycle.
	// Default: 100.
	BatchSize int

	Logger *logger.Logger
}

// ScanRetryController periodically checks for failed pipeline runs that are
// eligible for automatic retry (based on the parent scan's max_retries +
// retry_backoff_seconds with exponential backoff) and dispatches retries
// through the RetryDispatcher.
type ScanRetryController struct {
	runRepo    pipeline.RunRepository
	dispatcher RetryDispatcher
	config     *ScanRetryControllerConfig
	logger     *logger.Logger
}

// NewScanRetryController creates a new ScanRetryController.
func NewScanRetryController(
	runRepo pipeline.RunRepository,
	dispatcher RetryDispatcher,
	config *ScanRetryControllerConfig,
) *ScanRetryController {
	if config == nil {
		config = &ScanRetryControllerConfig{}
	}
	if config.Interval == 0 {
		config.Interval = 60 * time.Second
	}
	if config.BatchSize == 0 {
		config.BatchSize = 100
	}
	if config.Logger == nil {
		config.Logger = logger.NewNop()
	}

	return &ScanRetryController{
		runRepo:    runRepo,
		dispatcher: dispatcher,
		config:     config,
		logger:     config.Logger,
	}
}

func (c *ScanRetryController) Name() string         { return "scan-retry" }
func (c *ScanRetryController) Interval() time.Duration { return c.config.Interval }

func (c *ScanRetryController) Reconcile(ctx context.Context) (int, error) {
	if c.dispatcher == nil {
		return 0, nil
	}

	candidates, err := c.runRepo.ListPendingRetries(ctx, c.config.BatchSize)
	if err != nil {
		c.logger.Error("failed to list retry candidates", "error", err)
		return 0, err
	}

	if len(candidates) == 0 {
		return 0, nil
	}

	c.logger.Info("processing scan retry candidates", "count", len(candidates))

	processed := 0
	for _, cand := range candidates {
		nextAttempt := cand.RetryAttempt + 1
		if err := c.dispatcher.RetryScanRun(ctx, cand.TenantID, cand.ScanID, nextAttempt); err != nil {
			c.logger.Error("failed to dispatch scan retry",
				"scan_id", cand.ScanID.String(),
				"failed_run_id", cand.RunID.String(),
				"next_attempt", nextAttempt,
				"error", err)
			continue
		}
		c.logger.Info("dispatched scan retry",
			"scan_id", cand.ScanID.String(),
			"failed_run_id", cand.RunID.String(),
			"attempt", nextAttempt,
			"max_retries", cand.MaxRetries)
		processed++
	}

	return processed, nil
}
