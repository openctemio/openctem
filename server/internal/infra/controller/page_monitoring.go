package controller

// Web page monitoring dispatch and retention (docs/rfcs/RFC-138-web-page-monitoring.md).

import (
	"context"
	"time"

	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PageMonitorRunner dispatches due watches and sweeps old changes.
type PageMonitorRunner interface {
	Run(ctx context.Context, skip func(shared.ID) bool) (int, error)
	Sweep(ctx context.Context) (int64, error)
}

// PageMonitorController dispatches the due watches of every organization
// with the Attack surface module (every 10 minutes) and deletes changes past
// their retention once an hour.
type PageMonitorController struct {
	runner    PageMonitorRunner
	modules   ModuleGuard
	interval  time.Duration
	lastSweep time.Time
	now       func() time.Time
}

// NewPageMonitorController creates the controller (interval 0 = 10m).
func NewPageMonitorController(r PageMonitorRunner, modules ModuleGuard, interval time.Duration) *PageMonitorController {
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	return &PageMonitorController{runner: r, modules: modules, interval: interval, now: time.Now}
}

// Name implements Controller.
func (c *PageMonitorController) Name() string { return "page-monitoring" }

// Interval implements Controller.
func (c *PageMonitorController) Interval() time.Duration { return c.interval }

// Reconcile implements Controller.
func (c *PageMonitorController) Reconcile(ctx context.Context) (int, error) {
	if c.runner == nil {
		return 0, nil
	}
	if now := c.now(); now.Sub(c.lastSweep) >= time.Hour {
		c.lastSweep = now
		if _, err := c.runner.Sweep(ctx); err != nil {
			return 0, err
		}
	}
	cache := newTenantModuleCache(c.modules)
	return c.runner.Run(ctx, func(id shared.ID) bool {
		return cache.disabled(ctx, id.String(), moduledom.ModuleAttackSurface)
	})
}
