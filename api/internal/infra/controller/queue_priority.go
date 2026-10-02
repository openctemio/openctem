package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/logger"
)

// QueuePriorityControllerConfig configures the QueuePriorityController.
type QueuePriorityControllerConfig struct {
	// Interval is how often to recalculate queue priorities.
	// Default: 60 seconds.
	Interval time.Duration

	// Logger for logging.
	Logger *logger.Logger
}

// QueuePriorityController periodically recalculates queue priorities for platform jobs.
// This ensures fair scheduling across tenants by adjusting priorities based on:
// - Tenant's plan tier (higher tiers get base priority boost)
// - Job age (older jobs get priority bonus to prevent starvation)
// - Tenant's current queue depth (tenants with fewer jobs get slight boost)
//
// The priority calculation is done in the database for efficiency:
// new_priority = plan_base_priority + (wait_time_minutes * age_bonus_per_minute)
//
// This is a soft-priority system - higher priority jobs are processed first,
// but no tenant can completely starve others.
type QueuePriorityController struct {
	commandRepo command.Repository
	config      *QueuePriorityControllerConfig
	logger      *logger.Logger
}

// NewQueuePriorityController creates a new QueuePriorityController.
func NewQueuePriorityController(
	commandRepo command.Repository,
	config *QueuePriorityControllerConfig,
) *QueuePriorityController {
	if config == nil {
		config = &QueuePriorityControllerConfig{}
	}
	if config.Interval == 0 {
		config.Interval = 60 * time.Second
	}
	if config.Logger == nil {
		config.Logger = logger.NewNop()
	}

	return &QueuePriorityController{
		commandRepo: commandRepo,
		config:      config,
		logger:      config.Logger,
	}
}

// Name returns the controller name.
func (c *QueuePriorityController) Name() string {
	return "queue-priority"
}

// Interval returns the reconciliation interval.
func (c *QueuePriorityController) Interval() time.Duration {
	return c.config.Interval
}

// Reconcile recalculates queue priorities for all pending platform jobs.
func (c *QueuePriorityController) Reconcile(ctx context.Context) (int, error) {
	// Update priorities for all queued platform jobs
	updated, err := c.commandRepo.UpdateQueuePriorities(ctx)
	if err != nil {
		c.logger.Error("failed to update queue priorities",
			"error", err,
		)
		return 0, err
	}

	if updated > 0 {
		c.logger.Info("updated queue priorities",
			"count", updated,
		)
	}

	return int(updated), nil
}
