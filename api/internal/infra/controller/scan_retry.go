package controller

import (
	"context"
	"errors"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// RetryDispatcher is the dependency the ScanRetryController uses to actually
// re-trigger a failed scan run. The scan service implements this.
type RetryDispatcher interface {
	RetryScanRun(ctx context.Context, tenantID, scanID shared.ID, retryAttempt int) error
}

// retryRunRepository is the narrow slice of scanrun.RunRepository the
// ScanRetryController needs: claim eligible runs, and release a claim whose
// dispatch failed so the run is retried again next tick. scanrun.RunRepository
// satisfies it, so wiring passes the concrete repo unchanged.
type retryRunRepository interface {
	ListPendingRetries(ctx context.Context, limit int) ([]scanrun.RetryCandidate, error)
	ReleaseFailedRetryDispatch(ctx context.Context, runID shared.ID) error
}

// permanentDispatchCodes are trigger refusals a retry cannot fix (D7): the
// scanner is gone or disabled, the scan resolves to nothing, no sensor is
// available, the scan was paused. Such a run is not retried again; the next
// scheduled occurrence, or a manual trigger, starts fresh.
var permanentDispatchCodes = map[string]bool{
	"NO_SENSOR_AVAILABLE":  true,
	"NO_TARGETS":           true,
	"ALL_TARGETS_EXCLUDED": true,
	"TOOL_NOT_FOUND":       true,
	"TOOL_DISABLED":        true,
	"TOOL_NOT_SCANNER":     true,
	"NO_MATCHING_TOOL":     true,
	"STEP_INVALID":         true,
	"PIPELINE_NOT_FOUND":   true,
	"PIPELINE_DISABLED":    true,
	"PIPELINE_EMPTY":       true,
	"PIPELINE_NOT_SET":     true,
	"SCAN_NOT_TRIGGERABLE": true,
}

// isPermanentDispatchError reports whether a retry dispatch failed for a
// reason another attempt cannot fix.
func isPermanentDispatchError(err error) bool {
	var de *shared.DomainError
	return errors.As(err, &de) && permanentDispatchCodes[de.Code]
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

// ScanRetryController periodically checks for failed scan runs that are
// eligible for automatic retry (based on the parent scan's max_retries +
// retry_backoff_seconds with exponential backoff) and dispatches retries
// through the RetryDispatcher.
type ScanRetryController struct {
	runRepo    retryRunRepository
	dispatcher RetryDispatcher
	config     *ScanRetryControllerConfig
	logger     *logger.Logger
}

// NewScanRetryController creates a new ScanRetryController.
func NewScanRetryController(
	runRepo retryRunRepository,
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

func (c *ScanRetryController) Name() string            { return "scan-retry" }
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
			if isPermanentDispatchError(err) {
				// Leave the claim set: this run is not retried again.
				c.logger.Warn("scan retry not possible; giving up on this run",
					"scan_id", cand.ScanID.String(),
					"failed_run_id", cand.RunID.String(),
					"next_attempt", nextAttempt,
					"error", err)
				continue
			}
			c.logger.Error("failed to dispatch scan retry",
				"scan_id", cand.ScanID.String(),
				"failed_run_id", cand.RunID.String(),
				"next_attempt", nextAttempt,
				"error", err)
			// The dispatch was claimed at LIST time (retry_dispatched_at = NOW)
			// but created no new run. Release the claim and spend the attempt:
			// a dispatch that keeps failing must run out of budget (and back off
			// further each time), not be retried every interval forever.
			if relErr := c.runRepo.ReleaseFailedRetryDispatch(ctx, cand.RunID); relErr != nil {
				c.logger.Error("failed to release retry claim after dispatch failure",
					"scan_id", cand.ScanID.String(),
					"failed_run_id", cand.RunID.String(),
					"error", relErr)
			}
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
