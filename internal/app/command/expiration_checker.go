package command

import (
	"context"
	"encoding/json"
	"github.com/openctemio/api/internal/app"
	"sync"
	"time"

	"github.com/openctemio/api/internal/app/pipeline"
	commanddom "github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/logger"
)

// stepFailer is the slice of pipeline.Service this checker needs: a way to tell
// the owning run that the step it is waiting on is dead. Narrowed to an
// interface so the notification can be asserted in a test — silently skipping
// it is the failure mode this file exists to prevent.
type stepFailer interface {
	OnStepFailed(ctx context.Context, runID, stepKey, errorMessage, errorCode string) error
}

// ExpirationChecker periodically checks for expired commands and handles them.
type ExpirationChecker struct {
	commandRepo     commanddom.Repository
	pipelineService stepFailer
	logger          *logger.Logger

	interval        time.Duration
	maxQueueMinutes int
	stopCh          chan struct{}
	wg              sync.WaitGroup
}

// ExpirationCheckerConfig holds configuration for the command expiration checker.
type ExpirationCheckerConfig struct {
	// CheckInterval is how often to check for expired commands (default: 1 minute)
	CheckInterval time.Duration

	// MaxQueueMinutes is how long a platform job may sit in the dispatch queue
	// before it is expired (default: 60 minutes).
	MaxQueueMinutes int
}

// NewExpirationChecker creates a new ExpirationChecker.
func NewExpirationChecker(
	commandRepo commanddom.Repository,
	pipelineService *pipeline.Service,
	cfg ExpirationCheckerConfig,
	log *logger.Logger,
) *ExpirationChecker {
	interval := cfg.CheckInterval
	if interval == 0 {
		interval = time.Minute
	}

	maxQueueMinutes := cfg.MaxQueueMinutes
	if maxQueueMinutes == 0 {
		maxQueueMinutes = 60
	}

	// A nil *pipeline.Service wrapped in an interface is non-nil, which would
	// turn "no pipeline service configured" into a nil-pointer panic on the
	// first expired command. Keep the nil.
	var failer stepFailer
	if pipelineService != nil {
		failer = pipelineService
	}

	return &ExpirationChecker{
		commandRepo:     commandRepo,
		pipelineService: failer,
		logger:          log.With("component", "command_expiration_checker"),
		interval:        interval,
		maxQueueMinutes: maxQueueMinutes,
		stopCh:          make(chan struct{}),
	}
}

// Start starts the command expiration checker.
func (c *ExpirationChecker) Start() {
	c.wg.Add(1)
	go c.run()
	c.logger.Info("command expiration checker started", "interval", c.interval)
}

// Stop stops the command expiration checker gracefully.
func (c *ExpirationChecker) Stop() {
	close(c.stopCh)
	c.wg.Wait()
	c.logger.Info("command expiration checker stopped")
}

func (c *ExpirationChecker) run() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.checkAndExpire()
			c.checkAndExpireQueuedPlatformJobs()
		case <-c.stopCh:
			return
		}
	}
}

func (c *ExpirationChecker) checkAndExpire() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Find expired pending commands
	expiredCommands, err := c.commandRepo.FindExpired(ctx)
	if err != nil {
		c.logger.Error("failed to find expired commands", "error", err)
		return
	}

	if len(expiredCommands) == 0 {
		return
	}

	c.logger.Info("found expired commands", "count", len(expiredCommands))

	for _, cmd := range expiredCommands {
		c.handleExpiredCommand(ctx, cmd, expiryReasonCommand)
	}
}

// checkAndExpireQueuedPlatformJobs expires platform jobs that never got picked
// up out of the dispatch queue.
//
// This lives here, next to the tenant-command expiry, because it needs the same
// thing that expiry needs: a route back to the owning pipeline run.
// JobRecoveryController used to do it with a raw UPDATE, which reaped the row
// and told nobody — a platform job carries pipeline_run_id + step_key in its
// payload, and without OnStepFailed the step sat 'queued' until
// ScanTimeoutController reported a generic timeout minutes or hours later.
func (c *ExpirationChecker) checkAndExpireQueuedPlatformJobs() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	jobs, err := c.commandRepo.FindQueueExpiredPlatformJobs(ctx, c.maxQueueMinutes)
	if err != nil {
		c.logger.Error("failed to find queue-expired platform jobs", "error", err)
		return
	}

	if len(jobs) == 0 {
		return
	}

	c.logger.Info("found platform jobs expired in queue",
		"count", len(jobs), "max_queue_minutes", c.maxQueueMinutes)

	for _, cmd := range jobs {
		c.handleExpiredCommand(ctx, cmd, expiryReasonQueue)
	}
}

// expiryReason carries the message and code handed to pipeline.OnStepFailed, so
// the run records why the step died rather than a generic timeout.
type expiryReason struct {
	errorMessage string
	code         string
}

var (
	expiryReasonCommand = expiryReason{
		errorMessage: "Command expired without being executed",
		code:         "COMMAND_EXPIRED",
	}
	expiryReasonQueue = expiryReason{
		errorMessage: "Platform job expired in queue without being dispatched",
		code:         "PLATFORM_JOB_EXPIRED_IN_QUEUE",
	}
)

func (c *ExpirationChecker) handleExpiredCommand(ctx context.Context, cmd *commanddom.Command, reason expiryReason) {
	// Mark command as expired
	cmd.Expire()
	cmd.ErrorMessage = reason.errorMessage
	if err := c.commandRepo.Update(ctx, cmd); err != nil {
		c.logger.Error("failed to update expired command", "command_id", cmd.ID.String(), "error", err)
		return
	}

	// Record metric
	app.CommandsExpired.WithLabelValues(cmd.TenantID.String()).Inc()
	app.CommandsTotal.WithLabelValues(cmd.TenantID.String(), string(cmd.Type), "expired").Inc()

	c.logger.Info("command expired", "command_id", cmd.ID.String(), "reason", reason.code)

	// Trigger pipeline failure if this is a pipeline command
	if c.pipelineService != nil {
		c.triggerPipelineExpired(ctx, cmd, reason)
	}
}

func (c *ExpirationChecker) triggerPipelineExpired(ctx context.Context, cmd *commanddom.Command, reason expiryReason) {
	// Parse command payload to get pipeline info
	var payload struct {
		PipelineRunID string `json:"pipeline_run_id"`
		StepKey       string `json:"step_key"`
	}

	if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
		return // Not a pipeline command
	}

	if payload.PipelineRunID == "" || payload.StepKey == "" {
		return
	}

	// Trigger step failure with timeout error
	if err := c.pipelineService.OnStepFailed(ctx, payload.PipelineRunID, payload.StepKey, reason.errorMessage, reason.code); err != nil {
		c.logger.Error("failed to trigger pipeline expiration",
			"pipeline_run_id", payload.PipelineRunID,
			"step_key", payload.StepKey,
			"error", err,
		)
	}
}
