package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/server/pkg/logger"
)

// AIWorkerRunSettler ends runs on AI workers that can no longer get a result
// (aianalysis.Service.EndStaleWorkerRuns).
type AIWorkerRunSettler interface {
	EndStaleWorkerRuns(ctx context.Context) (int, error)
}

// AIWorkerRunSweepController ends, every interval, the runs on AI workers
// past their deadline or whose analysis job ended without a result
// (docs/architecture/ai-analysis.md), so a run never waits forever for a
// worker that is gone.
type AIWorkerRunSweepController struct {
	service  AIWorkerRunSettler
	interval time.Duration
	logger   *logger.Logger
}

// NewAIWorkerRunSweepController creates the controller.
func NewAIWorkerRunSweepController(service AIWorkerRunSettler, interval time.Duration, log *logger.Logger) *AIWorkerRunSweepController {
	if interval <= 0 {
		interval = time.Minute
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &AIWorkerRunSweepController{service: service, interval: interval, logger: log}
}

// Name returns the controller name.
func (c *AIWorkerRunSweepController) Name() string { return "ai-worker-run-sweep" }

// Interval returns the reconciliation interval.
func (c *AIWorkerRunSweepController) Interval() time.Duration { return c.interval }

// Reconcile runs one sweep.
func (c *AIWorkerRunSweepController) Reconcile(ctx context.Context) (int, error) {
	if c.service == nil {
		return 0, nil
	}
	n, err := c.service.EndStaleWorkerRuns(ctx)
	if err != nil {
		c.logger.Error("AI worker run sweep failed", "error", err)
		return 0, err
	}
	if n > 0 {
		c.logger.Info("AI worker runs ended without a result", "count", n)
	}
	return n, nil
}
