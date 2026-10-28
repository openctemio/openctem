package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// AIAnalystSweeper pauses AI analysts without an active accountable owner or
// with an attestation that ran out (aianalysis.Service.Sweep).
type AIAnalystSweeper interface {
	Sweep(ctx context.Context) (int, error)
}

// AIAnalystSweepController runs the AI analyst sweep
// (docs/architecture/ai-analysis.md). Every run start checks the same
// conditions (fail closed); the sweep makes the pause visible to owners and
// administrators without waiting for a run.
type AIAnalystSweepController struct {
	service  AIAnalystSweeper
	interval time.Duration
	logger   *logger.Logger
}

// NewAIAnalystSweepController creates the controller.
func NewAIAnalystSweepController(service AIAnalystSweeper, interval time.Duration, log *logger.Logger) *AIAnalystSweepController {
	if interval <= 0 {
		interval = time.Hour
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &AIAnalystSweepController{service: service, interval: interval, logger: log}
}

// Name returns the controller name.
func (c *AIAnalystSweepController) Name() string { return "ai-analyst-sweep" }

// Interval returns the reconciliation interval.
func (c *AIAnalystSweepController) Interval() time.Duration { return c.interval }

// Reconcile runs one sweep.
func (c *AIAnalystSweepController) Reconcile(ctx context.Context) (int, error) {
	if c.service == nil {
		return 0, nil
	}
	n, err := c.service.Sweep(ctx)
	if err != nil {
		c.logger.Error("AI analyst sweep failed", "error", err)
		return 0, err
	}
	if n > 0 {
		c.logger.Info("AI analysts paused", "count", n)
	}
	return n, nil
}
