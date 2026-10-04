package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/internal/app/easmdns"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// EASMDNSChecker is the slice of the EASM DNS service the controller runs.
type EASMDNSChecker interface {
	MonitorTenant(ctx context.Context, tenantID shared.ID) (easmdns.RunResult, error)
	MonitorEmail(ctx context.Context, tenantID shared.ID) (easmdns.RunResult, error)
}

// EASMDNSControllerConfig configures the daily DNS-only checks.
type EASMDNSControllerConfig struct {
	// Interval between sweeps. Default 24h (RFC-036 O9: daily light checks).
	Interval    time.Duration
	Logger      *logger.Logger
	ModuleGuard ModuleGuard
}

// EASMDNSController runs the dangling-DNS and email-posture checks for every
// active tenant with the attack-surface module. Per-tenant failures are
// logged and skipped (fail-open); only a tenant-list failure is returned.
type EASMDNSController struct {
	service    EASMDNSChecker
	tenantRepo tenant.Repository
	config     *EASMDNSControllerConfig
	logger     *logger.Logger
}

// NewEASMDNSController constructs the controller.
func NewEASMDNSController(service EASMDNSChecker, tenantRepo tenant.Repository, config *EASMDNSControllerConfig) *EASMDNSController {
	if config == nil {
		config = &EASMDNSControllerConfig{}
	}
	if config.Interval == 0 {
		config.Interval = 24 * time.Hour
	}
	if config.Logger == nil {
		config.Logger = logger.NewNop()
	}
	return &EASMDNSController{service: service, tenantRepo: tenantRepo, config: config,
		logger: config.Logger.With("controller", "easm-dns-checks")}
}

// Name implements Controller.
func (c *EASMDNSController) Name() string { return "easm-dns-checks" }

// Interval implements Controller.
func (c *EASMDNSController) Interval() time.Duration { return c.config.Interval }

// Reconcile implements Controller. Returns how many tenants were checked.
func (c *EASMDNSController) Reconcile(ctx context.Context) (int, error) {
	if c.service == nil || c.tenantRepo == nil {
		return 0, nil
	}
	ids, err := c.tenantRepo.ListActiveTenantIDs(ctx)
	if err != nil {
		return 0, err
	}
	modules := newTenantModuleCache(c.config.ModuleGuard)
	checked := 0
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return checked, err
		}
		if modules.disabled(ctx, id.String(), moduledom.ModuleAttackSurface) {
			continue
		}
		if _, err := c.service.MonitorTenant(ctx, id); err != nil {
			c.logger.Warn("dangling-DNS check failed; continuing", "tenant_id", id.String(), "error", err)
		}
		if _, err := c.service.MonitorEmail(ctx, id); err != nil {
			c.logger.Warn("email-posture check failed; continuing", "tenant_id", id.String(), "error", err)
		}
		checked++
	}
	return checked, nil
}
