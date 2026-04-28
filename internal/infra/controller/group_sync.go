package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/logger"
)

// GroupSyncControllerConfig configures the GroupSyncController.
type GroupSyncControllerConfig struct {
	// Interval is how often to run the sync.
	// Default: 1 hour.
	Interval time.Duration

	// Logger for logging.
	Logger *logger.Logger
}

// GroupSyncController periodically synchronizes groups from external providers.
// It implements the Controller interface and is managed by the controller Manager.
//
// This controller:
// 1. Iterates over all active tenants
// 2. For each tenant, triggers SyncAll to synchronize all configured providers
// 3. Logs sync results for monitoring
//
// NOT WIRED: this controller is not registered in cmd/server/workers.go
// because app.GroupSyncService is also not constructed in services.go —
// the periodic sync side of the group-provider feature is not shipped.
// On-demand sync works through the HTTP handler (group_handler.go). A
// future PR that turns on periodic SCIM/LDAP sync needs to:
//   1. Construct app.NewGroupSyncService(repos.Group, log) in services.go
//   2. Register this controller in workers.go
type GroupSyncController struct {
	syncService *app.GroupSyncService
	tenantRepo  tenant.Repository
	config      *GroupSyncControllerConfig
	logger      *logger.Logger
}

// NewGroupSyncController creates a new GroupSyncController.
func NewGroupSyncController(
	syncService *app.GroupSyncService,
	tenantRepo tenant.Repository,
	config *GroupSyncControllerConfig,
) *GroupSyncController {
	if config == nil {
		config = &GroupSyncControllerConfig{}
	}
	if config.Interval == 0 {
		config.Interval = 1 * time.Hour
	}
	if config.Logger == nil {
		config.Logger = logger.NewNop()
	}

	return &GroupSyncController{
		syncService: syncService,
		tenantRepo:  tenantRepo,
		config:      config,
		logger:      config.Logger,
	}
}

// Name returns the controller name.
func (c *GroupSyncController) Name() string {
	return "group-sync"
}

// Interval returns the reconciliation interval.
func (c *GroupSyncController) Interval() time.Duration {
	return c.config.Interval
}

// Reconcile performs the periodic group sync across all active tenants.
// Returns the number of tenants synced and any error encountered.
func (c *GroupSyncController) Reconcile(ctx context.Context) (int, error) {
	tenantIDs, err := c.tenantRepo.ListActiveTenantIDs(ctx)
	if err != nil {
		c.logger.Error("failed to list active tenants for group sync", "error", err)
		return 0, err
	}

	syncedCount := 0
	for _, tenantID := range tenantIDs {
		if err := c.syncService.SyncAll(ctx, tenantID); err != nil {
			c.logger.Error("failed to sync groups for tenant",
				"tenant_id", tenantID.String(),
				"error", err,
			)
			continue
		}
		syncedCount++
	}

	if syncedCount > 0 {
		c.logger.Info("group sync completed",
			"tenants_synced", syncedCount,
			"total_tenants", len(tenantIDs),
		)
	}

	return syncedCount, nil
}

// TriggerSync manually triggers a sync for a specific tenant.
// This is used by the HTTP handler for on-demand sync requests.
func (c *GroupSyncController) TriggerSync(ctx context.Context, tenantID shared.ID) error {
	return c.syncService.SyncAll(ctx, tenantID)
}
