package controller

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/logger"
)

// OwnerResolutionController periodically resolves asset ownership by matching
// owner_ref (email/username text) to actual user accounts.
//
// When a scanner ingests an asset, it may set owner_ref (e.g., "alice@example.com")
// but cannot know the internal user UUID. This controller finds those assets and
// populates owner_id from the users table.
//
// Runs every 30 minutes.
type OwnerResolutionController struct {
	db     *sql.DB
	logger *logger.Logger
}

// NewOwnerResolutionController creates a new controller.
func NewOwnerResolutionController(db *sql.DB, log *logger.Logger) *OwnerResolutionController {
	return &OwnerResolutionController{db: db, logger: log}
}

// Name returns the controller name.
func (c *OwnerResolutionController) Name() string { return "owner-resolution" }

// Interval returns 30 minutes.
func (c *OwnerResolutionController) Interval() time.Duration { return 30 * time.Minute }

// Reconcile resolves owner_ref to owner_id for assets missing owner_id.
// Uses a single UPDATE with JOIN for efficiency.
func (c *OwnerResolutionController) Reconcile(ctx context.Context) (int, error) {
	// Match owner_ref (case-insensitive) against users.email
	// Only processes assets with owner_ref set but owner_id NULL
	query := `
		UPDATE assets a SET
			owner_id = u.id,
			updated_at = NOW()
		FROM users u, tenant_members tm
		WHERE a.owner_id IS NULL
		  AND a.owner_ref IS NOT NULL
		  AND a.owner_ref != ''
		  AND LOWER(u.email) = LOWER(a.owner_ref)
		  AND tm.user_id = u.id
		  AND tm.tenant_id = a.tenant_id
	`
	result, err := c.db.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("owner resolution: %w", err)
	}

	resolved, _ := result.RowsAffected()
	if resolved > 0 {
		c.logger.Info("owner resolution complete",
			"assets_resolved", resolved,
		)
	}
	return int(resolved), nil
}
