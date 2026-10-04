package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/metrics"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/logger"
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
	// to a sensor without being picked up before being reassigned.
	// Default: 10 minutes (shorter than platform jobs as tenant sensors poll more frequently).
	TenantStuckThresholdMinutes int

	// MaxRetries is the maximum number of retry attempts for a job.
	// After this many retries, the job will be marked as failed.
	// Default: 3.
	MaxRetries int

	// Logger for logging.
	Logger *logger.Logger
}

// JobRecoveryController recovers stuck jobs and re-queues them.
// This is a K8s-style controller that ensures jobs don't get lost if a sensor
// goes offline or fails to complete them.
//
// The controller performs two main tasks:
//  1. Recover stuck jobs: Return jobs to the queue if they've been assigned
//     but haven't progressed (sensor went offline or crashed) — both platform
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
	steps       StepFailureNotifier
}

// StepFailureNotifier is told when a pipeline step's command died here.
// Satisfied by the pipeline service.
type StepFailureNotifier interface {
	OnStepFailed(ctx context.Context, runID, stepKey, errorMessage, errorCode string) error
}

// SetStepFailureNotifier wires the pipeline: a command failed for exhausting
// its dispatch attempts then fails its step (and settles the run) right away,
// instead of the run hanging until the run timeout reports a generic
// "no result reported before timeout".
func (c *JobRecoveryController) SetStepFailureNotifier(n StepFailureNotifier) { c.steps = n }

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
		config.TenantStuckThresholdMinutes = 10 // Shorter for tenant sensors
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

	// Step 2: Recover stuck tenant commands (assigned to offline sensors)
	// This handles the race condition where a sensor is selected but goes offline
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

	// Step 2b: Release pending work pinned to a sensor that went offline or
	// was disabled. Without it a zone batch pinned at trigger time to a sensor
	// that then died waited for the run timeout (RFC-030 B7).
	released, err := c.commandRepo.ReleasePendingFromUnavailableSensors(ctx)
	if err != nil {
		c.logger.Error("failed to release pending commands of unavailable sensors",
			"error", err,
		)
	} else if released > 0 {
		c.logger.Info("released pending commands pinned to unavailable sensors",
			"count", released,
		)
		totalProcessed += int(released)
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
	//
	// Both raw-UPDATE reapers have since been deleted from the repository
	// entirely, so this cannot be reintroduced by accident: expiry has exactly
	// one implementation and it notifies the run.

	// Step 2c: Take back commands whose lease ran out (RFC-035 D6): the
	// sensor holding them stopped renewing (it died, or lost them), so they
	// go back to the queue now instead of at the run timeout. The holder can
	// no longer complete them (fenced by sensor, state and lease epoch).
	if reaper, ok := c.commandRepo.(command.LeaseReaper); ok {
		requeued, err := reaper.RequeueExpiredLeases(ctx)
		if err != nil {
			c.logger.Error("failed to re-queue commands with an expired lease", "error", err)
		} else if len(requeued) > 0 {
			metrics.CommandLeasesExpiredTotal.Add(float64(len(requeued)))
			for _, rq := range requeued {
				holder := ""
				if rq.SensorID != nil {
					holder = rq.SensorID.String()
				}
				c.logger.Info("re-queued command: its lease ran out",
					"command_id", rq.ID.String(), "tenant_id", rq.TenantID.String(),
					"sensor_id", holder, "lease_epoch", rq.Epoch)
			}
			totalProcessed += len(requeued)
		}
	}

	// Step 3: Fail commands that have exceeded max retry attempts, and tell
	// their pipeline runs (poison commands).
	if failer, ok := c.commandRepo.(command.ExhaustedFailer); ok && c.steps != nil {
		failed, err := failer.FailExhaustedCommandsReturning(ctx, c.config.MaxRetries)
		if err != nil {
			c.logger.Error("failed to mark exhausted commands as failed", "error", err)
		} else if len(failed) > 0 {
			c.logger.Info("marked exhausted commands as failed",
				"count", len(failed), "max_retries", c.config.MaxRetries)
			c.notifyExhausted(ctx, failed)
			totalProcessed += len(failed)
		}
		return totalProcessed, nil
	}
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

// notifyExhausted fails the pipeline step of each exhausted command.
func (c *JobRecoveryController) notifyExhausted(ctx context.Context, failed []*command.Command) {
	for _, cmd := range failed {
		var p pipeline.StepCommandPayload
		if err := json.Unmarshal(cmd.Payload, &p); err != nil || !p.IsRoutable() {
			continue // not a pipeline command
		}
		msg := fmt.Sprintf("the command was handed to a sensor %d times and never finished (max dispatch attempts exceeded)", cmd.DispatchAttempts)
		if err := c.steps.OnStepFailed(ctx, p.PipelineRunID, p.StepKey, msg, pipeline.FailureCommandExhausted); err != nil {
			c.logger.Error("failed to fail the pipeline step of an exhausted command",
				"command_id", cmd.ID.String(), "pipeline_run_id", p.PipelineRunID, "step_key", p.StepKey, "error", err)
		}
	}
}
