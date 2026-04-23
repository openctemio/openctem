package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/internal/app/asset"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/logger"
)

// AssetLifecycleControllerConfig configures the daily stale-detection
// pass. The controller itself holds no per-tenant state; it drives
// the worker against every tenant on the cron cadence.
type AssetLifecycleControllerConfig struct {
	// Interval is how often to run. Default: 24h. Lifecycle is
	// inherently slow-moving (asset thresholds are measured in days)
	// so sub-daily cron frequency would only add DB churn without
	// changing outcomes.
	Interval time.Duration

	// Logger for structured log output. Defaults to NewNop when nil.
	Logger *logger.Logger
}

// AssetLifecycleController fans the lifecycle worker out across
// tenants. Each tenant is handled serially to keep the implementation
// predictable — the worker's SQL is cheap (indexed scan) and a
// tenant with millions of assets is still sub-second. If we ever
// need parallelism we can add a tunable here without changing the
// controller's external interface.
type AssetLifecycleController struct {
	worker     *asset.AssetLifecycleWorker
	tenantRepo tenant.Repository
	config     *AssetLifecycleControllerConfig
	logger     *logger.Logger
}

// NewAssetLifecycleController constructs the controller.
func NewAssetLifecycleController(
	worker *asset.AssetLifecycleWorker,
	tenantRepo tenant.Repository,
	config *AssetLifecycleControllerConfig,
) *AssetLifecycleController {
	if config == nil {
		config = &AssetLifecycleControllerConfig{}
	}
	if config.Interval == 0 {
		config.Interval = 24 * time.Hour
	}
	if config.Logger == nil {
		config.Logger = logger.NewNop()
	}
	return &AssetLifecycleController{
		worker:     worker,
		tenantRepo: tenantRepo,
		config:     config,
		logger:     config.Logger.With("controller", "asset-lifecycle"),
	}
}

// Name implements controller.Controller.
func (c *AssetLifecycleController) Name() string { return "asset-lifecycle" }

// Interval implements controller.Controller.
func (c *AssetLifecycleController) Interval() time.Duration { return c.config.Interval }

// Reconcile iterates every tenant and invokes the worker against
// those that have opted in. Returns the total number of assets
// transitioned across all tenants so the reconciler metrics line
// up with actual work done.
//
// Errors on individual tenants are logged but not returned — one
// broken tenant should not halt the pass for every other tenant.
// Unrecoverable failures (e.g. tenant repo lookup) do return an
// error so the controller runner can retry on the next tick.
func (c *AssetLifecycleController) Reconcile(ctx context.Context) (int, error) {
	// ListActiveTenantIDs returns only non-archived tenants, which
	// is exactly what we want — we do not run lifecycle for deleted
	// or suspended orgs.
	tenantIDs, err := c.tenantRepo.ListActiveTenantIDs(ctx)
	if err != nil {
		return 0, err
	}

	total := 0
	for _, tenantID := range tenantIDs {
		t, err := c.tenantRepo.GetByID(ctx, tenantID)
		if err != nil {
			c.logger.Warn("failed to load tenant for lifecycle run",
				"tenant_id", tenantID.String(),
				"error", err,
			)
			continue
		}
		settings := t.TypedSettings().AssetLifecycle
		if !settings.Enabled {
			continue
		}

		// Honor per-tenant opt-in. Feature-disabled tenants skip
		// without even touching the worker.
		report, err := c.worker.Run(ctx, tenantID, false)
		if err != nil {
			c.logger.Warn("asset lifecycle run failed; continuing with next tenant",
				"tenant_id", tenantID.String(),
				"error", err,
			)
			continue
		}

		if report.Skipped {
			c.logger.Info("asset lifecycle skipped",
				"tenant_id", tenantID.String(),
				"reason", report.SkipReason,
			)
			continue
		}

		total += report.TransitionedToStale
		if report.TransitionedToStale > 0 {
			c.logger.Info("asset lifecycle transitions applied",
				"tenant_id", tenantID.String(),
				"transitioned_to_stale", report.TransitionedToStale,
				"threshold_days", report.StaleThresholdDays,
			)
		}
	}

	return total, nil
}
