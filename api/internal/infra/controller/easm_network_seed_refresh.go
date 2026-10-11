package controller

// Weekly refresh of network seeds (docs/rfcs/RFC-082-network-seeds.md).

import (
	"context"
	"time"

	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// NetworkSeedRefresher expands due network seeds.
type NetworkSeedRefresher interface {
	RefreshDue(ctx context.Context, skip func(shared.ID) bool) (int, error)
}

// EASMNetworkSeedController refreshes network seeds from public routing data
// once a week (it ticks every 6 hours and takes the due ones).
type EASMNetworkSeedController struct {
	refresher NetworkSeedRefresher
	modules   ModuleGuard
	interval  time.Duration
}

// NewEASMNetworkSeedController creates the controller (interval 0 = 6h).
func NewEASMNetworkSeedController(r NetworkSeedRefresher, modules ModuleGuard, interval time.Duration) *EASMNetworkSeedController {
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	return &EASMNetworkSeedController{refresher: r, modules: modules, interval: interval}
}

// Name implements Controller.
func (c *EASMNetworkSeedController) Name() string { return "easm-network-seed-refresh" }

// Interval implements Controller.
func (c *EASMNetworkSeedController) Interval() time.Duration { return c.interval }

// Reconcile implements Controller.
func (c *EASMNetworkSeedController) Reconcile(ctx context.Context) (int, error) {
	if c.refresher == nil {
		return 0, nil
	}
	cache := newTenantModuleCache(c.modules)
	return c.refresher.RefreshDue(ctx, func(id shared.ID) bool {
		return cache.disabled(ctx, id.String(), moduledom.ModuleAttackSurface)
	})
}
