package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// IdleWorkspaceSweeper moves idle Free organizations through the lifecycle
// (lifecycle.Service.Sweep).
type IdleWorkspaceSweeper interface {
	Sweep(ctx context.Context) (int, error)
}

// IdleWorkspaceController runs the idle-workspace sweep
// (docs/architecture/idle-workspaces.md), every few hours.
type IdleWorkspaceController struct {
	service  IdleWorkspaceSweeper
	interval time.Duration
	logger   *logger.Logger
}

// NewIdleWorkspaceController creates the controller.
func NewIdleWorkspaceController(service IdleWorkspaceSweeper, interval time.Duration, log *logger.Logger) *IdleWorkspaceController {
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &IdleWorkspaceController{service: service, interval: interval, logger: log}
}

// Name returns the controller name.
func (c *IdleWorkspaceController) Name() string { return "idle-workspaces" }

// Interval returns the reconciliation interval.
func (c *IdleWorkspaceController) Interval() time.Duration { return c.interval }

// Reconcile runs one sweep.
func (c *IdleWorkspaceController) Reconcile(ctx context.Context) (int, error) {
	if c.service == nil {
		return 0, nil
	}
	n, err := c.service.Sweep(ctx)
	if err != nil {
		c.logger.Error("idle workspace sweep failed", "error", err)
		return 0, err
	}
	if n > 0 {
		c.logger.Info("idle workspaces changed stage", "count", n)
	}
	return n, nil
}
