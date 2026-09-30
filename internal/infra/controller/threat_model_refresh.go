package controller

import (
	"context"
	"time"

	moduledom "github.com/openctemio/api/pkg/domain/module"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
	tmdom "github.com/openctemio/api/pkg/domain/threatmodel"
	"github.com/openctemio/api/pkg/logger"
)

// ThreatModelRefreshControllerConfig configures the periodic threat-model
// regeneration pass.
type ThreatModelRefreshControllerConfig struct {
	// Interval is how often to run. Default: 2h. Threat models are derived
	// from exposure chains, asset-graph edges, attacker profiles and live
	// findings, which move slower than the hourly graph-enrichment pass that
	// feeds them, so a 2h cadence is enough to keep threats current. The
	// generator has built-in no-op detection (InputHash unchanged since the
	// last generation short-circuits the write), so over-running is cheap.
	Interval time.Duration

	// Logger for structured output. Defaults to NewNop when nil.
	Logger *logger.Logger

	// ModuleGuard, when set, skips tenants that have disabled the threat-model
	// module — no point regenerating a threat model a tenant turned off.
	// Optional; nil means "never skip" (fully backward compatible).
	ModuleGuard ModuleGuard
}

// threatModelGenerator is the app-layer surface the controller drives per
// tenant. Implemented by *threatmodel.Service.
type threatModelGenerator interface {
	GenerateForScope(ctx context.Context, tenantID shared.ID, scopeType tmdom.ScopeType, scopeRefID *shared.ID) (*tmdom.ThreatModel, error)
}

// ThreatModelRefreshController periodically regenerates each tenant's
// tenant-wide threat model so it reflects the latest exposure chains and
// asset-graph edges (e.g. edges the graph-enrichment controller just
// inferred). Without this, threat_model_threats only changes when a user
// manually triggers generation through the API, leaving the
// priority-classification threat-model oracle reading stale data.
//
// A background controller (rather than the ingest hot path) is used because
// generation reasons over the whole tenant graph and must not slow ingest.
// The generator is idempotent (InputHash no-op detection) and each tenant is
// handled serially; a failure on one tenant never halts the others.
type ThreatModelRefreshController struct {
	generator   threatModelGenerator
	tenantRepo  tenant.Repository
	config      *ThreatModelRefreshControllerConfig
	logger      *logger.Logger
	moduleGuard ModuleGuard
}

// NewThreatModelRefreshController constructs the controller.
func NewThreatModelRefreshController(
	generator threatModelGenerator,
	tenantRepo tenant.Repository,
	config *ThreatModelRefreshControllerConfig,
) *ThreatModelRefreshController {
	if config == nil {
		config = &ThreatModelRefreshControllerConfig{}
	}
	if config.Interval == 0 {
		config.Interval = 2 * time.Hour
	}
	if config.Logger == nil {
		config.Logger = logger.NewNop()
	}
	return &ThreatModelRefreshController{
		generator:   generator,
		tenantRepo:  tenantRepo,
		config:      config,
		logger:      config.Logger.With("controller", "threat-model-refresh"),
		moduleGuard: config.ModuleGuard,
	}
}

// Name implements controller.Controller.
func (c *ThreatModelRefreshController) Name() string { return "threat-model-refresh" }

// Interval implements controller.Controller.
func (c *ThreatModelRefreshController) Interval() time.Duration { return c.config.Interval }

// Reconcile regenerates the tenant-wide threat model for every active
// tenant. Returns the number of tenants successfully (re)generated.
// Per-tenant errors are logged and skipped; only an unrecoverable
// tenant-list failure is returned so the runner retries next tick.
func (c *ThreatModelRefreshController) Reconcile(ctx context.Context) (int, error) {
	tenantIDs, err := c.tenantRepo.ListActiveTenantIDs(ctx)
	if err != nil {
		return 0, err
	}

	modules := newTenantModuleCache(c.moduleGuard)
	regenerated := 0
	for _, tenantID := range tenantIDs {
		// Skip a tenant that has turned the threat-model module off
		// (nil guard / no override → never skips).
		if modules.disabled(ctx, tenantID.String(), moduledom.ModuleThreatModel) {
			continue
		}
		if _, err := c.generator.GenerateForScope(ctx, tenantID, tmdom.ScopeTenant, nil); err != nil {
			c.logger.Warn("threat model refresh failed; continuing with next tenant",
				"tenant_id", tenantID.String(), "error", err)
			continue
		}
		regenerated++
	}
	return regenerated, nil
}
