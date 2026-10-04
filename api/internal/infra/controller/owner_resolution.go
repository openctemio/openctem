package controller

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// OwnerResolutionController periodically resolves asset ownership by matching
// owner_ref (email/username text) to actual user accounts.
//
// When a scanner ingests an asset, it may set owner_ref (e.g., "alice@example.com")
// but cannot know the internal user UUID. This controller finds those assets and
// adds the matching tenant member as a primary owner in asset_owners (source
// 'owner_ref'), the one owner model. Such an owner never grants data access.
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

// ownerResolutionQuery adds the member whose email equals owner_ref
// (case-insensitive) as the asset's primary owner, unless the asset already has
// an owner_ref-derived owner or that member already owns the asset in any role
// (an explicit RACI choice is never overridden). The member must belong to the
// asset's tenant. The unique index (asset_id, user_id) makes it idempotent.
const ownerResolutionQuery = `
	INSERT INTO asset_owners (asset_id, user_id, ownership_type, assigned_at, assignment_source)
	SELECT a.id, u.id, 'primary', NOW(), 'owner_ref'
	FROM assets a
	JOIN users u ON LOWER(u.email) = LOWER(a.owner_ref)
	JOIN tenant_members tm ON tm.user_id = u.id AND tm.tenant_id = a.tenant_id
	WHERE a.deleted_at IS NULL
	  AND a.owner_ref IS NOT NULL
	  AND a.owner_ref LIKE '%@%'
	  AND NOT EXISTS (
	      SELECT 1 FROM asset_owners ao
	      WHERE ao.asset_id = a.id
	        AND (ao.user_id = u.id OR ao.assignment_source = 'owner_ref')
	  )
	ON CONFLICT DO NOTHING
`

// Reconcile resolves owner_ref to a primary owner for assets that have none
// derived from it yet. Uses a single INSERT ... SELECT for efficiency.
func (c *OwnerResolutionController) Reconcile(ctx context.Context) (int, error) {
	result, err := c.db.ExecContext(ctx, ownerResolutionQuery)
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
