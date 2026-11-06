package controller

import (
	"context"
	"database/sql"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// RoleSyncControllerConfig configures the RoleSyncController.
type RoleSyncControllerConfig struct {
	// Interval is how often to run the sync check.
	// Default: 1 hour.
	Interval time.Duration

	// Logger for logging.
	Logger *logger.Logger
}

// RoleSyncController repairs the one membership/role inconsistency that is
// never a legitimate state: a tenant owner (tenant_members.role = 'owner')
// without the owner role in user_roles.
//
// user_roles is the RBAC role set and is authoritative: it is exactly what an
// administrator granted (custom roles, several roles, or none).
// tenant_members.role is only a coarse label derived from that set
// (accesscontrol.MembershipRoleForRoleIDs). This controller used to re-insert
// the system role named by the label whenever the user lacked it, which
// silently restored privileges every hour: a user created with only a custom
// role got 'viewer' back, a removed system role came back, an admin gained an
// extra 'member' row.
//
// It never grants anything else. A member with no roles at all (possible
// after a restore, or because an administrator removed every role) is only
// reported, since the two cannot be told apart.
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

// Reconcile restores the owner role of tenant owners who lack it, and reports
// active members who hold no role.
func (c *RoleSyncController) Reconcile(ctx context.Context) (int, error) {
	query := `
		INSERT INTO user_roles (user_id, role_id, tenant_id, assigned_at)
		SELECT tm.user_id, r.id, tm.tenant_id, COALESCE(tm.joined_at, NOW())
		FROM tenant_members tm
		JOIN roles r ON r.slug = 'owner' AND r.is_system = TRUE AND r.tenant_id IS NULL
		WHERE tm.role = 'owner'
		  AND NOT EXISTS (
			SELECT 1 FROM user_roles ur
			WHERE ur.user_id = tm.user_id AND ur.tenant_id = tm.tenant_id AND ur.role_id = r.id
		  )
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
		c.logger.Warn("restored the owner role of tenant owners who lacked it",
			"count", rowsAffected,
		)
	}

	var roleless int
	if err := c.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM tenant_members tm
		WHERE tm.status = 'active'
		  AND NOT EXISTS (
			SELECT 1 FROM user_roles ur
			WHERE ur.user_id = tm.user_id AND ur.tenant_id = tm.tenant_id
		  )
	`).Scan(&roleless); err != nil {
		return int(rowsAffected), err
	}
	if roleless > 0 {
		c.logger.Info("active members with no role (no access until an administrator assigns one)",
			"count", roleless,
		)
	}

	return int(rowsAffected), nil
}
