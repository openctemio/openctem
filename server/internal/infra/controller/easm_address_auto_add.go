package controller

// Strong addresses behind in-scope names become scope entries
// (research/425; internal/app/easm/address_autoadd.go).

import (
	"context"
	"time"

	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AddressAutoAdder adds the strong addresses of every seeded tenant.
type AddressAutoAdder interface {
	Run(ctx context.Context, skip func(shared.ID) bool) (int, error)
}

// EASMAddressAutoAddController runs the address auto add every 30 minutes,
// skipping tenants whose attack surface module is off.
type EASMAddressAutoAddController struct {
	adder    AddressAutoAdder
	modules  ModuleGuard
	interval time.Duration
}

// NewEASMAddressAutoAddController creates the controller (interval 0 = 30m).
func NewEASMAddressAutoAddController(a AddressAutoAdder, modules ModuleGuard, interval time.Duration) *EASMAddressAutoAddController {
	if interval <= 0 {
		interval = 30 * time.Minute
	}
	return &EASMAddressAutoAddController{adder: a, modules: modules, interval: interval}
}

// Name implements Controller.
func (c *EASMAddressAutoAddController) Name() string { return "easm-address-auto-add" }

// Interval implements Controller.
func (c *EASMAddressAutoAddController) Interval() time.Duration { return c.interval }

// Reconcile implements Controller.
func (c *EASMAddressAutoAddController) Reconcile(ctx context.Context) (int, error) {
	if c.adder == nil {
		return 0, nil
	}
	cache := newTenantModuleCache(c.modules)
	return c.adder.Run(ctx, func(id shared.ID) bool {
		return cache.disabled(ctx, id.String(), moduledom.ModuleAttackSurface)
	})
}
