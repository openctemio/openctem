package controller

// Passive lookalike-domain checks (docs/rfcs/RFC-083-lookalike-domains.md).

import (
	"context"
	"time"

	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// LookalikeRunner checks due lookalike candidates.
type LookalikeRunner interface {
	Run(ctx context.Context, skip func(shared.ID) bool) (int, error)
}

// EASMLookalikeController runs the passive lookalike checks every hour; each
// run takes a bounded batch of due candidates per tenant (registered ones
// daily, others weekly).
type EASMLookalikeController struct {
	runner   LookalikeRunner
	modules  ModuleGuard
	interval time.Duration
}

// NewEASMLookalikeController creates the controller (interval 0 = 1h).
func NewEASMLookalikeController(r LookalikeRunner, modules ModuleGuard, interval time.Duration) *EASMLookalikeController {
	if interval <= 0 {
		interval = time.Hour
	}
	return &EASMLookalikeController{runner: r, modules: modules, interval: interval}
}

// Name implements Controller.
func (c *EASMLookalikeController) Name() string { return "easm-lookalikes" }

// Interval implements Controller.
func (c *EASMLookalikeController) Interval() time.Duration { return c.interval }

// Reconcile implements Controller.
func (c *EASMLookalikeController) Reconcile(ctx context.Context) (int, error) {
	if c.runner == nil {
		return 0, nil
	}
	cache := newTenantModuleCache(c.modules)
	return c.runner.Run(ctx, func(id shared.ID) bool {
		return cache.disabled(ctx, id.String(), moduledom.ModuleAttackSurface)
	})
}
