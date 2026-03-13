package controller

import (
	"context"
	"database/sql"
	"time"

	"github.com/openctemio/api/pkg/logger"
)

// RoleSyncControllerConfig configures the RoleSyncController.
type RoleSyncControllerConfig struct {
	// Interval is how often to run the sync check.
	// Default: 1 hour.
	Interval time.Duration

	// Logger for logging.
	Logger *logger.Logger
}

// RoleSyncController ensures tenant_members and user_roles stay in sync.
//
// The RBAC permission system reads from user_roles, while tenant_members stores
// the canonical membership. A trigger (sync_tenant_member_to_user_roles) handles
// new INSERT/UPDATE, but entries can become desynced after:
//   - Database restore from backup
//   - Migration rollback and re-apply
//   - Manual data manipulation
//   - Trigger being temporarily disabled
//
// This controller detects missing user_roles entries and backfills them,
// preventing "Access Denied" errors for affected users.
type RoleSyncController struct {
	db     *sql.DB
	config *RoleSyncControllerConfig
	logger *logger.Logger
}

// NewRoleSyncController creates a new RoleSyncController.
func NewRoleSyncController(
	db *sql.DB,
	config *RoleSyncControllerConfig,
) *RoleSyncController {
	if config == nil {
		config = &RoleSyncControllerConfig{}
	}
	if config.Interval == 0 {
		config.Interval = 1 * time.Hour
	}
	if config.Logger == nil {
		config.Logger = logger.NewNop()
	}

	return &RoleSyncController{
		db:     db,
		config: config,
		logger: config.Logger,
	}
}

// Name returns the controller name.
func (c *RoleSyncController) Name() string {
	return "role-sync"
}

// Interval returns the reconciliation interval.
func (c *RoleSyncController) Interval() time.Duration {
	return c.config.Interval
}

// Reconcile detects and fixes missing user_roles entries.
func (c *RoleSyncController) Reconcile(ctx context.Context) (int, error) {
	// Backfill missing user_roles from tenant_members
	query := `
		INSERT INTO user_roles (user_id, role_id, tenant_id, assigned_at)
		SELECT tm.user_id, r.id, tm.tenant_id, COALESCE(tm.joined_at, NOW())
		FROM tenant_members tm
		JOIN roles r ON r.slug = tm.role AND r.is_system = TRUE AND r.tenant_id IS NULL
		LEFT JOIN user_roles ur
			ON ur.user_id = tm.user_id
			AND ur.tenant_id = tm.tenant_id
			AND ur.role_id = r.id
		WHERE ur.user_id IS NULL
		ON CONFLICT (user_id, role_id, tenant_id) DO NOTHING
	`

	result, err := c.db.ExecContext(ctx, query)
	if err != nil {
		return 0, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}

	if rowsAffected > 0 {
		c.logger.Warn("backfilled missing user_roles entries",
			"count", rowsAffected,
		)
	}

	return int(rowsAffected), nil
}
