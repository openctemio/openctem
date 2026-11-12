package controller

// Weekly attack-surface digest (docs/rfcs/RFC-080-attack-surface-changes-and-digest.md).

import (
	"context"
	"time"

	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// EASMDigestSender sends one tenant's weekly digest when it is due.
type EASMDigestSender interface {
	RunTenant(ctx context.Context, tenantID shared.ID) (bool, error)
}

// EASMWeeklyDigestController ticks hourly; each active tenant with the
// attack-surface module gets its digest once per slot (the slot claim in the
// database makes it once across replicas). Per-tenant failures are logged
// and retried on the next tick.
type EASMWeeklyDigestController struct {
	sender     EASMDigestSender
	tenantRepo tenant.Repository
	modules    ModuleGuard
	interval   time.Duration
	logger     *logger.Logger
}

// NewEASMWeeklyDigestController creates the controller (interval 0 = 1h).
func NewEASMWeeklyDigestController(sender EASMDigestSender, tenantRepo tenant.Repository, modules ModuleGuard,
	interval time.Duration, log *logger.Logger) *EASMWeeklyDigestController {
	if interval <= 0 {
		interval = time.Hour
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &EASMWeeklyDigestController{sender: sender, tenantRepo: tenantRepo, modules: modules, interval: interval,
		logger: log.With("controller", "easm-weekly-digest")}
}

// Name implements Controller.
func (c *EASMWeeklyDigestController) Name() string { return "easm-weekly-digest" }

// Interval implements Controller.
func (c *EASMWeeklyDigestController) Interval() time.Duration { return c.interval }

// Reconcile implements Controller. Returns how many digests went out.
func (c *EASMWeeklyDigestController) Reconcile(ctx context.Context) (int, error) {
	if c.sender == nil || c.tenantRepo == nil {
		return 0, nil
	}
	ids, err := c.tenantRepo.ListActiveTenantIDs(ctx)
	if err != nil {
		return 0, err
	}
	modules := newTenantModuleCache(c.modules)
	sent := 0
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return sent, err
		}
		if modules.disabled(ctx, id.String(), moduledom.ModuleAttackSurface) {
			continue
		}
		ok, err := c.sender.RunTenant(ctx, id)
		if err != nil {
			c.logger.Warn("weekly digest failed; retried next tick", "tenant_id", id.String(), "error", logger.SanitizeError(err))
			continue
		}
		if ok {
			sent++
		}
	}
	return sent, nil
}
