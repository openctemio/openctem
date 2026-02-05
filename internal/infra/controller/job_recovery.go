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

	// MaxQueueMinutes is how long a job can wait in the queue before expiring.
	// Default: 60 minutes.
	MaxQueueMinutes int

	// Logger for logging.
	Logger *logger.Logger
}

// JobRecoveryController recovers stuck jobs and re-queues them.
// This is a K8s-style controller that ensures jobs don't get lost if an agent
// goes offline or fails to complete them.
//
// The controller performs three main tasks:
//  1. Recover stuck jobs: Return jobs to the queue if they've been assigned
//     but haven't progressed (agent went offline or crashed)
//  2. Expire old jobs: Mark jobs as expired if they've been in queue too long
//  3. Clean up: Mark orphaned jobs as failed if they exceed retry limit
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
	if config.MaxQueueMinutes == 0 {
		config.MaxQueueMinutes = 60
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

	// Step 3: Expire platform jobs that have been in queue too long
	expired, err := c.commandRepo.ExpireOldPlatformJobs(ctx, c.config.MaxQueueMinutes)
	if err != nil {
		c.logger.Error("failed to expire old platform jobs",
			"error", err,
		)
		return totalProcessed, err
	}

	if expired > 0 {
		c.logger.Info("expired old platform jobs",
			"count", expired,
			"max_queue_minutes", c.config.MaxQueueMinutes,
		)
	}
	totalProcessed += int(expired)

	// Step 4: Expire regular commands that have passed their expiration time
	expiredCommands, err := c.commandRepo.ExpireOldCommands(ctx)
	if err != nil {
		c.logger.Error("failed to expire old commands",
			"error", err,
		)
		return totalProcessed, err
	}

	if expiredCommands > 0 {
		c.logger.Info("expired old commands",
			"count", expiredCommands,
		)
	}
	totalProcessed += int(expiredCommands)

	// Step 5: Fail commands that have exceeded max retry attempts
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
