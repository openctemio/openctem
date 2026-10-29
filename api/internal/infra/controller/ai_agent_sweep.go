package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// AIAgentSweeper pauses AI agents without an active accountable owner or
// with an attestation that ran out (aianalysis.Service.Sweep).
type AIAgentSweeper interface {
	Sweep(ctx context.Context) (int, error)
}

// AIAgentSweepController runs the AI agent sweep
// (docs/architecture/ai-analysis.md). Every run start checks the same
// conditions (fail closed); the sweep makes the pause visible to owners and
// administrators without waiting for a run.
type AIAgentSweepController struct {
	service  AIAgentSweeper
	interval time.Duration
	logger   *logger.Logger
}

// NewAIAgentSweepController creates the controller.
func NewAIAgentSweepController(service AIAgentSweeper, interval time.Duration, log *logger.Logger) *AIAgentSweepController {
	if interval <= 0 {
		interval = time.Hour
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &AIAgentSweepController{service: service, interval: interval, logger: log}
}

// Name returns the controller name.
func (c *AIAgentSweepController) Name() string { return "ai-agent-sweep" }

// Interval returns the reconciliation interval.
func (c *AIAgentSweepController) Interval() time.Duration { return c.interval }

// Reconcile runs one sweep.
func (c *AIAgentSweepController) Reconcile(ctx context.Context) (int, error) {
	if c.service == nil {
		return 0, nil
	}
	n, err := c.service.Sweep(ctx)
	if err != nil {
		c.logger.Error("AI agent sweep failed", "error", err)
		return 0, err
	}
	if n > 0 {
		c.logger.Info("AI agents paused", "count", n)
	}
	return n, nil
}
