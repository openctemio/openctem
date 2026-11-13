package controller

// The exploration loop (docs/architecture/exploration.md): rules open leads,
// finished steps settle, the best open leads are dispatched through the
// coverage run path.

import (
	"context"
	"time"
)

// ExplorationRunner runs one pass of the exploration loop.
type ExplorationRunner interface {
	Run(ctx context.Context) (int, error)
}

// ExplorationController runs the exploration loop on one replica at a time.
type ExplorationController struct {
	runner   ExplorationRunner
	interval time.Duration
}

// NewExplorationController creates the controller (interval default 2m).
func NewExplorationController(runner ExplorationRunner, interval time.Duration) *ExplorationController {
	if interval <= 0 {
		interval = 2 * time.Minute
	}
	return &ExplorationController{runner: runner, interval: interval}
}

// Name returns the controller name.
func (c *ExplorationController) Name() string { return "exploration" }

// Interval returns how often the controller runs.
func (c *ExplorationController) Interval() time.Duration { return c.interval }

// Exclusive: one replica runs the loop at a time.
func (c *ExplorationController) Exclusive() bool { return true }

// Reconcile runs one pass.
func (c *ExplorationController) Reconcile(ctx context.Context) (int, error) {
	return c.runner.Run(ctx)
}
