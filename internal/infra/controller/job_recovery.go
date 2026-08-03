package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/logger"
)

// JobRecoveryControllerConfig configures the JobRecoveryController.
type JobRecoveryControllerConfig struct {
	// Interval is how often to run the job recovery check.
	// Default: 60 seconds.
	Interval time.Duration

	// StuckThresholdMinutes is how long a job can be in acknowledged/running state
	// without progress before being considered stuck.
	// Default: 30 minutes.
	StuckThresholdMinutes int

	// TenantStuckThresholdMinutes is how long a tenant command can be assigned
	// to an agent without being picked up before being reassigned.
	// Default: 10 minutes (shorter than platform jobs as tenant agents poll more frequently).
	TenantStuckThresholdMinutes int

	// MaxRetries is the maximum number of retry attempts for a job.
	// After this many retries, the job will be marked as failed.
	// Default: 3.
	MaxRetries int

	// Logger for logging.
	Logger *logger.Logger
}

// JobRecoveryController recovers stuck jobs and re-queues them.
// This is a K8s-style controller that ensures jobs don't get lost if an agent
// goes offline or fails to complete them.
//
// The controller performs two main tasks:
//  1. Recover stuck jobs: Return jobs to the queue if they've been assigned
//     but haven't progressed (agent went offline or crashed) — both platform
//     jobs and tenant commands
//  2. Clean up: Mark orphaned jobs as failed if they exceed retry limit
//
// Expiry is NOT this controller's job — see the note in Reconcile;
// app/command.ExpirationChecker owns it, because expiry has to notify the
// owning pipeline run and a raw UPDATE here cannot.
type JobRecoveryController struct {
	commandRepo command.Repository
	config      *JobRecoveryControllerConfig
	logger      *logger.Logger
}

// NewJobRecoveryController creates a new JobRecoveryController.
func NewJobRecoveryController(
	commandRepo command.Repository,
	config *JobRecoveryControllerConfig,
) *JobRecoveryController {
	if config == nil {
		config = &JobRecoveryControllerConfig{}
	}
	if config.Interval == 0 {
		config.Interval = 60 * time.Second
	}
	if config.StuckThresholdMinutes == 0 {
		config.StuckThresholdMinutes = 30
	}
	if config.TenantStuckThresholdMinutes == 0 {
		config.TenantStuckThresholdMinutes = 10 // Shorter for tenant agents
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.Logger == nil {
		config.Logger = logger.NewNop()
	}

	return &JobRecoveryController{
		commandRepo: commandRepo,
		config:      config,
		logger:      config.Logger,
	}
}

// Name returns the controller name.
func (c *JobRecoveryController) Name() string {
	return "job-recovery"
}

// Interval returns the reconciliation interval.
func (c *JobRecoveryController) Interval() time.Duration {
	return c.config.Interval
}

// Reconcile recovers stuck jobs and expires old ones.
func (c *JobRecoveryController) Reconcile(ctx context.Context) (int, error) {
	totalProcessed := 0

	// Step 1: Recover stuck platform jobs (assigned but not progressing)
	recovered, err := c.commandRepo.RecoverStuckJobs(
		ctx,
		c.config.StuckThresholdMinutes,
		c.config.MaxRetries,
	)
	if err != nil {
		c.logger.Error("failed to recover stuck platform jobs",
			"error", err,
		)
		return 0, err
	}

	if recovered > 0 {
		c.logger.Info("recovered stuck platform jobs",
			"count", recovered,
			"stuck_threshold_minutes", c.config.StuckThresholdMinutes,
		)
	}
	totalProcessed += int(recovered)

	// Step 2: Recover stuck tenant commands (assigned to offline agents)
	// This handles the race condition where an agent is selected but goes offline
	// before picking up the command.
	recoveredTenant, err := c.commandRepo.RecoverStuckTenantCommands(
		ctx,
		c.config.TenantStuckThresholdMinutes,
		c.config.MaxRetries,
	)
	if err != nil {
		c.logger.Error("failed to recover stuck tenant commands",
			"error", err,
		)
		// Continue with other recovery tasks, don't fail entirely
	} else if recoveredTenant > 0 {
		c.logger.Info("recovered stuck tenant commands",
			"count", recoveredTenant,
			"stuck_threshold_minutes", c.config.TenantStuckThresholdMinutes,
		)
		totalProcessed += int(recoveredTenant)
	}

	// NOTE: expiry is deliberately NOT done here — neither for regular
	// (non-platform) commands nor for queued platform jobs.
	// app/command.ExpirationChecker owns both: it calls
	// pipeline.OnStepFailed(..., "COMMAND_EXPIRED" / "PLATFORM_JOB_EXPIRED_IN_QUEUE")
	// so the owning pipeline run learns its step died.
	//
	// This controller used to run commandRepo.ExpireOldCommands() on the same
	// 60s tick — a raw UPDATE over a strict subset of the same rows. Whenever it
	// won that race the row flipped to 'expired' before FindExpired() saw it,
	// and the run was never notified, so a scan hung until some other timeout
	// caught it. ExpireOldPlatformJobs was the identical mistake one step over,
	// and worse: platform jobs are created with expires_at NULL, so FindExpired
	// never covered them at all and the raw UPDATE was the *only* thing that
	// ever reaped them. Every platform job that timed out in the queue took its
	// pipeline run down silently, and the run hung until ScanTimeoutController
	// reported a generic timeout instead of "expired in queue".

	// Step 3: Fail commands that have exceeded max retry attempts
	failedExhausted, err := c.commandRepo.FailExhaustedCommands(ctx, c.config.MaxRetries)
	if err != nil {
		c.logger.Error("failed to mark exhausted commands as failed",
			"error", err,
		)
		// Don't fail entirely, continue
	} else if failedExhausted > 0 {
		c.logger.Info("marked exhausted commands as failed",
			"count", failedExhausted,
			"max_retries", c.config.MaxRetries,
		)
		totalProcessed += int(failedExhausted)
	}

	return totalProcessed, nil
}
