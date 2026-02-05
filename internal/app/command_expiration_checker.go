package app

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/openctemio/api/internal/app/pipeline"
	"github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/logger"
)

// CommandExpirationChecker periodically checks for expired commands and handles them.
type CommandExpirationChecker struct {
	commandRepo     command.Repository
	pipelineService *pipeline.Service
	logger          *logger.Logger

	interval time.Duration
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// CommandExpirationCheckerConfig holds configuration for the command expiration checker.
type CommandExpirationCheckerConfig struct {
	// CheckInterval is how often to check for expired commands (default: 1 minute)
	CheckInterval time.Duration
}

// NewCommandExpirationChecker creates a new CommandExpirationChecker.
func NewCommandExpirationChecker(
	commandRepo command.Repository,
	pipelineService *pipeline.Service,
	cfg CommandExpirationCheckerConfig,
	log *logger.Logger,
) *CommandExpirationChecker {
	interval := cfg.CheckInterval
	if interval == 0 {
		interval = time.Minute
	}

	return &CommandExpirationChecker{
		commandRepo:     commandRepo,
		pipelineService: pipelineService,
		logger:          log.With("component", "command_expiration_checker"),
		interval:        interval,
		stopCh:          make(chan struct{}),
	}
}

// Start starts the command expiration checker.
func (c *CommandExpirationChecker) Start() {
	c.wg.Add(1)
	go c.run()
	c.logger.Info("command expiration checker started", "interval", c.interval)
}

// Stop stops the command expiration checker gracefully.
func (c *CommandExpirationChecker) Stop() {
	close(c.stopCh)
	c.wg.Wait()
	c.logger.Info("command expiration checker stopped")
}

func (c *CommandExpirationChecker) run() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.checkAndExpire()
		case <-c.stopCh:
			return
		}
	}
}

func (c *CommandExpirationChecker) checkAndExpire() {
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
		c.handleExpiredCommand(ctx, cmd)
	}
}

func (c *CommandExpirationChecker) handleExpiredCommand(ctx context.Context, cmd *command.Command) {
	// Mark command as expired
	cmd.Expire()
	if err := c.commandRepo.Update(ctx, cmd); err != nil {
		c.logger.Error("failed to update expired command", "command_id", cmd.ID.String(), "error", err)
		return
	}

	// Record metric
	CommandsExpired.WithLabelValues(cmd.TenantID.String()).Inc()
	CommandsTotal.WithLabelValues(cmd.TenantID.String(), string(cmd.Type), "expired").Inc()

	c.logger.Info("command expired", "command_id", cmd.ID.String())

	// Trigger pipeline failure if this is a pipeline command
	if c.pipelineService != nil {
		c.triggerPipelineExpired(ctx, cmd)
	}
}

func (c *CommandExpirationChecker) triggerPipelineExpired(ctx context.Context, cmd *command.Command) {
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
	if err := c.pipelineService.OnStepFailed(ctx, payload.PipelineRunID, payload.StepKey, "Command expired without being executed", "COMMAND_EXPIRED"); err != nil {
		c.logger.Error("failed to trigger pipeline expiration",
			"pipeline_run_id", payload.PipelineRunID,
			"step_key", payload.StepKey,
			"error", err,
		)
	}
}
