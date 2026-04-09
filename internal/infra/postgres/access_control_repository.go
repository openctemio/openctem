package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/accesscontrol"
	"github.com/openctemio/api/pkg/domain/shared"
)

// AccessControlRepository implements accesscontrol.Repository using PostgreSQL.
type AccessControlRepository struct {
	db *DB
}

// NewAccessControlRepository creates a new AccessControlRepository.
func NewAccessControlRepository(db *DB) *AccessControlRepository {
	return &AccessControlRepository{db: db}
}

// =============================================================================
// ASSET OWNERSHIP
// =============================================================================

// CreateAssetOwner creates a new asset ownership relationship.
// Supports both group-level and user-level (direct) ownership.
func (r *AccessControlRepository) CreateAssetOwner(ctx context.Context, ao *accesscontrol.AssetOwner) error {
	query := `
		INSERT INTO asset_owners (id, asset_id, group_id, user_id, ownership_type, assigned_at, assigned_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	var groupID, userID, assignedBy any
	if ao.GroupID() != nil {
		groupID = ao.GroupID().String()
	}
	if ao.UserID() != nil {
		userID = ao.UserID().String()
	}
	if ao.AssignedBy() != nil {
		assignedBy = ao.AssignedBy().String()
	}

	_, err := r.db.ExecContext(ctx, query,
		ao.ID().String(),
		ao.AssetID().String(),
		groupID,
		userID,
		ao.OwnershipType().String(),
		ao.AssignedAt(),
		assignedBy,
	)
	if err != nil {
		// Check for unique constraint violation
		if isUniqueViolation(err) {
			return accesscontrol.ErrAssetOwnerExists
		}
		return fmt.Errorf("failed to create asset owner: %w", err)
	}

	return nil
}

// GetAssetOwner retrieves an asset ownership by asset and group ID.
func (r *AccessControlRepository) GetAssetOwner(ctx context.Context, assetID, groupID shared.ID) (*accesscontrol.AssetOwner, error) {
	query := `
		SELECT id, asset_id, group_id, user_id, ownership_type, assigned_at, assigned_by
		FROM asset_owners
		WHERE asset_id = $1 AND group_id = $2
	`

	var (
		idStr         string
		assetIDStr    string
		groupIDStr    sql.NullString
		userIDStr     sql.NullString
		ownershipType string
		assignedAt    sql.NullTime
		assignedBy    sql.NullString
	)

	err := r.db.QueryRowContext(ctx, query, assetID.String(), groupID.String()).Scan(
		&idStr,
		&assetIDStr,
		&groupIDStr,
		&userIDStr,
		&ownershipType,
		&assignedAt,
		&assignedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, accesscontrol.ErrAssetOwnerNotFound
		}
		return nil, fmt.Errorf("failed to get asset owner: %w", err)
	}

	return r.scanAssetOwner(idStr, assetIDStr, groupIDStr, userIDStr, ownershipType, assignedAt, assignedBy)
}

// GetAssetOwnerByID retrieves an asset ownership by its ID.
func (r *AccessControlRepository) GetAssetOwnerByID(ctx context.Context, id shared.ID) (*accesscontrol.AssetOwner, error) {
	query := `
		SELECT id, asset_id, group_id, user_id, ownership_type, assigned_at, assigned_by
		FROM asset_owners
		WHERE id = $1
	`

	var (
		idStr         string
		assetIDStr    string
		groupIDStr    sql.NullString
		userIDStr     sql.NullString
		ownershipType string
		assignedAt    sql.NullTime
		assignedBy    sql.NullString
	)

	err := r.db.QueryRowContext(ctx, query, id.String()).Scan(
		&idStr,
		&assetIDStr,
		&groupIDStr,
		&userIDStr,
		&ownershipType,
		&assignedAt,
		&assignedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, accesscontrol.ErrAssetOwnerNotFound
		}
		return nil, fmt.Errorf("failed to get asset owner by ID: %w", err)
	}

	return r.scanAssetOwner(idStr, assetIDStr, groupIDStr, userIDStr, ownershipType, assignedAt, assignedBy)
}

// GetAssetOwnerByUser retrieves an asset ownership by asset and user ID (direct ownership).
func (r *AccessControlRepository) GetAssetOwnerByUser(ctx context.Context, assetID, userID shared.ID) (*accesscontrol.AssetOwner, error) {
	query := `
		SELECT id, asset_id, group_id, user_id, ownership_type, assigned_at, assigned_by
		FROM asset_owners
		WHERE asset_id = $1 AND user_id = $2
	`

	var (
		idStr         string
		assetIDStr    string
		groupIDStr    sql.NullString
		userIDStr     sql.NullString
		ownershipType string
		assignedAt    sql.NullTime
		assignedBy    sql.NullString
	)

	err := r.db.QueryRowContext(ctx, query, assetID.String(), userID.String()).Scan(
		&idStr,
		&assetIDStr,
		&groupIDStr,
		&userIDStr,
		&ownershipType,
		&assignedAt,
		&assignedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, accesscontrol.ErrAssetOwnerNotFound
		}
		return nil, fmt.Errorf("failed to get asset owner by user: %w", err)
	}

	return r.scanAssetOwner(idStr, assetIDStr, groupIDStr, userIDStr, ownershipType, assignedAt, assignedBy)
}

// UpdateAssetOwner updates an existing asset ownership.
func (r *AccessControlRepository) UpdateAssetOwner(ctx context.Context, ao *accesscontrol.AssetOwner) error {
	query := `
		UPDATE asset_owners
		SET ownership_type = $1
		WHERE id = $2
	`

	result, err := r.db.ExecContext(ctx, query,
		ao.OwnershipType().String(),
		ao.ID().String(),
	)
	if err != nil {
		return fmt.Errorf("failed to update asset owner: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return accesscontrol.ErrAssetOwnerNotFound
	}

	return nil
}

// DeleteAssetOwner removes an asset ownership by asset and group ID.
func (r *AccessControlRepository) DeleteAssetOwner(ctx context.Context, assetID, groupID shared.ID) error {
	query := `DELETE FROM asset_owners WHERE asset_id = $1 AND group_id = $2`

	result, err := r.db.ExecContext(ctx, query, assetID.String(), groupID.String())
	if err != nil {
		return fmt.Errorf("failed to delete asset owner: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return accesscontrol.ErrAssetOwnerNotFound
	}

	return nil
}

// DeleteAssetOwnerByID removes an asset ownership by its ID.
func (r *AccessControlRepository) DeleteAssetOwnerByID(ctx context.Context, id shared.ID) error {
	query := `DELETE FROM asset_owners WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete asset owner by ID: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return accesscontrol.ErrAssetOwnerNotFound
	}

	return nil
}

// DeleteAssetOwnerByUser removes an asset ownership by asset and user ID (direct ownership).
func (r *AccessControlRepository) DeleteAssetOwnerByUser(ctx context.Context, assetID, userID shared.ID) error {
	query := `DELETE FROM asset_owners WHERE asset_id = $1 AND user_id = $2`

	result, err := r.db.ExecContext(ctx, query, assetID.String(), userID.String())
	if err != nil {
		return fmt.Errorf("failed to delete asset owner by user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return accesscontrol.ErrAssetOwnerNotFound
	}

	return nil
}

// ListAssetOwners lists all owners of an asset (both group and user ownership).
func (r *AccessControlRepository) ListAssetOwners(ctx context.Context, assetID shared.ID) ([]*accesscontrol.AssetOwner, error) {
	query := `
		SELECT id, asset_id, group_id, user_id, ownership_type, assigned_at, assigned_by
		FROM asset_owners
		WHERE asset_id = $1
		ORDER BY
			CASE ownership_type
				WHEN 'primary' THEN 1
				WHEN 'secondary' THEN 2
				WHEN 'stakeholder' THEN 3
				WHEN 'informed' THEN 4
			END,
			assigned_at
	`

	rows, err := r.db.QueryContext(ctx, query, assetID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list asset owners: %w", err)
	}
	defer rows.Close()

	var owners []*accesscontrol.AssetOwner
	for rows.Next() {
		var (
			idStr         string
			assetIDStr    string
			groupIDStr    sql.NullString
			userIDStr     sql.NullString
			ownershipType string
			assignedAt    sql.NullTime
			assignedBy    sql.NullString
		)

		if err := rows.Scan(&idStr, &assetIDStr, &groupIDStr, &userIDStr, &ownershipType, &assignedAt, &assignedBy); err != nil {
			return nil, fmt.Errorf("failed to scan asset owner: %w", err)
		}

		ao, err := r.scanAssetOwner(idStr, assetIDStr, groupIDStr, userIDStr, ownershipType, assignedAt, assignedBy)
		if err != nil {
			return nil, err
		}
		owners = append(owners, ao)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating asset owners: %w", err)
	}

	return owners, nil
}

// ListAssetsByGroup lists all asset IDs owned by a group.
func (r *AccessControlRepository) ListAssetsByGroup(ctx context.Context, groupID shared.ID) ([]shared.ID, error) {
	query := `
		SELECT asset_id
		FROM asset_owners
		WHERE group_id = $1
		ORDER BY assigned_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, groupID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list assets by group: %w", err)
	}
	defer rows.Close()

	var assetIDs []shared.ID
	for rows.Next() {
		var assetIDStr string
		if err := rows.Scan(&assetIDStr); err != nil {
			return nil, fmt.Errorf("failed to scan asset ID: %w", err)
		}

		assetID, err := shared.IDFromString(assetIDStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse asset ID: %w", err)
		}
		assetIDs = append(assetIDs, assetID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating assets: %w", err)
	}

	return assetIDs, nil
}

// ListAssetOwnersByGroupWithDetails lists asset owners for a group with asset name/type/status, with pagination.
func (r *AccessControlRepository) ListAssetOwnersByGroupWithDetails(ctx context.Context, groupID shared.ID, limit, offset int) ([]*accesscontrol.AssetOwnerWithAsset, int64, error) {
	// Apply pagination defaults and caps.
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	// Count total asset owners for this group.
	countQuery := `SELECT COUNT(*) FROM asset_owners WHERE group_id = $1`
	var totalCount int64
	if err := r.db.QueryRowContext(ctx, countQuery, groupID.String()).Scan(&totalCount); err != nil {
		return nil, 0, fmt.Errorf("failed to count asset owners with details: %w", err)
	}

	query := `
		SELECT ao.id, ao.asset_id, ao.group_id, ao.user_id, ao.ownership_type, ao.assigned_at, ao.assigned_by,
		       COALESCE(a.name, ''), COALESCE(a.asset_type, ''), COALESCE(a.status, '')
		FROM asset_owners ao
		LEFT JOIN assets a ON a.id = ao.asset_id
		WHERE ao.group_id = $1
		ORDER BY ao.assigned_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.db.QueryContext(ctx, query, groupID.String(), limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list asset owners with details: %w", err)
	}
	defer rows.Close()

	var results []*accesscontrol.AssetOwnerWithAsset
	for rows.Next() {
		var (
			idStr, assetIDStr, ownershipType, assignedAt string
			groupIDStr, userIDStr, assignedByStr          *string
			assetName, assetType, assetStatus             string
		)
		if err := rows.Scan(&idStr, &assetIDStr, &groupIDStr, &userIDStr, &ownershipType, &assignedAt, &assignedByStr,
			&assetName, &assetType, &assetStatus); err != nil {
			return nil, 0, fmt.Errorf("failed to scan asset owner with details: %w", err)
		}

		id, _ := shared.IDFromString(idStr)
		assetID, _ := shared.IDFromString(assetIDStr)

		var gid *shared.ID
		if groupIDStr != nil {
			g, _ := shared.IDFromString(*groupIDStr)
			gid = &g
		}
		var uid *shared.ID
		if userIDStr != nil {
			u, _ := shared.IDFromString(*userIDStr)
			uid = &u
		}
		var assignedBy *shared.ID
		if assignedByStr != nil {
			ab, _ := shared.IDFromString(*assignedByStr)
			assignedBy = &ab
		}

		parsedTime, _ := time.Parse(time.RFC3339, assignedAt)

		ao := accesscontrol.ReconstituteAssetOwner(id, assetID, gid, uid,
			accesscontrol.OwnershipType(ownershipType), parsedTime, assignedBy)

		results = append(results, &accesscontrol.AssetOwnerWithAsset{
			AssetOwner:  ao,
			AssetName:   assetName,
			AssetType:   assetType,
			AssetStatus: assetStatus,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return results, totalCount, nil
}

// ListGroupsByAsset lists all group IDs that own an asset (excludes direct user ownership).
func (r *AccessControlRepository) ListGroupsByAsset(ctx context.Context, assetID shared.ID) ([]shared.ID, error) {
	query := `
		SELECT group_id
		FROM asset_owners
		WHERE asset_id = $1 AND group_id IS NOT NULL
		ORDER BY
			CASE ownership_type
				WHEN 'primary' THEN 1
				WHEN 'secondary' THEN 2
				WHEN 'stakeholder' THEN 3
				WHEN 'informed' THEN 4
			END
	`

	rows, err := r.db.QueryContext(ctx, query, assetID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list groups by asset: %w", err)
	}
	defer rows.Close()

	var groupIDs []shared.ID
	for rows.Next() {
		var groupIDStr string
		if err := rows.Scan(&groupIDStr); err != nil {
			return nil, fmt.Errorf("failed to scan group ID: %w", err)
		}

		groupID, err := shared.IDFromString(groupIDStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse group ID: %w", err)
		}
		groupIDs = append(groupIDs, groupID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating groups: %w", err)
	}

	return groupIDs, nil
}

// ListUsersByAsset lists all user IDs that directly own an asset.
func (r *AccessControlRepository) ListUsersByAsset(ctx context.Context, assetID shared.ID) ([]shared.ID, error) {
	query := `
		SELECT user_id
		FROM asset_owners
		WHERE asset_id = $1 AND user_id IS NOT NULL
		ORDER BY
			CASE ownership_type
				WHEN 'primary' THEN 1
				WHEN 'secondary' THEN 2
				WHEN 'stakeholder' THEN 3
				WHEN 'informed' THEN 4
			END
	`

	rows, err := r.db.QueryContext(ctx, query, assetID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list users by asset: %w", err)
	}
	defer rows.Close()

	var userIDs []shared.ID
	for rows.Next() {
		var userIDStr string
		if err := rows.Scan(&userIDStr); err != nil {
			return nil, fmt.Errorf("failed to scan user ID: %w", err)
		}

		userID, err := shared.IDFromString(userIDStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse user ID: %w", err)
		}
		userIDs = append(userIDs, userID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating users: %w", err)
	}

	return userIDs, nil
}

// ListAssetsByUser lists all asset IDs directly owned by a user.
func (r *AccessControlRepository) ListAssetsByUser(ctx context.Context, userID shared.ID) ([]shared.ID, error) {
	query := `
		SELECT asset_id
		FROM asset_owners
		WHERE user_id = $1
		ORDER BY assigned_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list assets by user: %w", err)
	}
	defer rows.Close()

	var assetIDs []shared.ID
	for rows.Next() {
		var assetIDStr string
		if err := rows.Scan(&assetIDStr); err != nil {
			return nil, fmt.Errorf("failed to scan asset ID: %w", err)
		}

		assetID, err := shared.IDFromString(assetIDStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse asset ID: %w", err)
		}
		assetIDs = append(assetIDs, assetID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating assets: %w", err)
	}

	return assetIDs, nil
}

// CountAssetOwners counts the number of owners for an asset.
func (r *AccessControlRepository) CountAssetOwners(ctx context.Context, assetID shared.ID) (int64, error) {
	query := `SELECT COUNT(*) FROM asset_owners WHERE asset_id = $1`

	var count int64
	err := r.db.QueryRowContext(ctx, query, assetID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count asset owners: %w", err)
	}

	return count, nil
}

// CountAssetsByGroups counts assets owned by multiple groups in a single query.
func (r *AccessControlRepository) CountAssetsByGroups(ctx context.Context, groupIDs []shared.ID) (map[shared.ID]int, error) {
	if len(groupIDs) == 0 {
		return make(map[shared.ID]int), nil
	}

	ids := make([]string, len(groupIDs))
	for i, id := range groupIDs {
		ids[i] = id.String()
	}

	query := `SELECT group_id, COUNT(DISTINCT asset_id) FROM asset_owners WHERE group_id = ANY($1) GROUP BY group_id`

	rows, err := r.db.QueryContext(ctx, query, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("failed to count assets by groups: %w", err)
	}
	defer rows.Close()

	result := make(map[shared.ID]int, len(groupIDs))
	for rows.Next() {
		var gidStr string
		var count int
		if err := rows.Scan(&gidStr, &count); err != nil {
			return nil, fmt.Errorf("failed to scan asset count: %w", err)
		}
		gid, _ := shared.IDFromString(gidStr)
		result[gid] = count
	}

	return result, rows.Err()
}

// HasPrimaryOwner checks if an asset has at least one primary owner.
func (r *AccessControlRepository) HasPrimaryOwner(ctx context.Context, assetID shared.ID) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM asset_owners
			WHERE asset_id = $1 AND ownership_type = 'primary'
		)
	`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, assetID.String()).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check primary owner: %w", err)
	}

	return exists, nil
}

// scanAssetOwner converts database values to an AssetOwner domain entity.
func (r *AccessControlRepository) scanAssetOwner(
	idStr, assetIDStr string,
	groupIDStr, userIDStr sql.NullString,
	ownershipType string,
	assignedAt sql.NullTime,
	assignedBy sql.NullString,
) (*accesscontrol.AssetOwner, error) {
	id, err := shared.IDFromString(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ID: %w", err)
	}

	assetID, err := shared.IDFromString(assetIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse asset ID: %w", err)
	}

	var groupID *shared.ID
	if groupIDStr.Valid {
		gid, err := shared.IDFromString(groupIDStr.String)
		if err != nil {
			return nil, fmt.Errorf("failed to parse group ID: %w", err)
		}
		groupID = &gid
	}

	var userID *shared.ID
	if userIDStr.Valid {
		uid, err := shared.IDFromString(userIDStr.String)
		if err != nil {
			return nil, fmt.Errorf("failed to parse user ID: %w", err)
		}
		userID = &uid
	}

	var assignedByID *shared.ID
	if assignedBy.Valid {
		abid, err := shared.IDFromString(assignedBy.String)
		if err != nil {
			return nil, fmt.Errorf("failed to parse assigned_by ID: %w", err)
		}
		assignedByID = &abid
	}

	return accesscontrol.ReconstituteAssetOwner(
		id,
		assetID,
		groupID,
		userID,
		accesscontrol.OwnershipType(ownershipType),
		assignedAt.Time,
		assignedByID,
	), nil
}

// =============================================================================
// USER-ASSET ACCESS QUERIES
// =============================================================================

// ListAccessibleAssets returns all asset IDs a user can access within a tenant.
func (r *AccessControlRepository) ListAccessibleAssets(ctx context.Context, tenantID, userID shared.ID) ([]shared.ID, error) {
	// Use the materialized view for performance
	query := `
		SELECT DISTINCT asset_id
		FROM user_accessible_assets
		WHERE tenant_id = $1 AND user_id = $2
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), userID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list accessible assets: %w", err)
	}
	defer rows.Close()

	var assetIDs []shared.ID
	for rows.Next() {
		var assetIDStr string
		if err := rows.Scan(&assetIDStr); err != nil {
			return nil, fmt.Errorf("failed to scan asset ID: %w", err)
		}

		assetID, err := shared.IDFromString(assetIDStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse asset ID: %w", err)
		}
		assetIDs = append(assetIDs, assetID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating accessible assets: %w", err)
	}

	return assetIDs, nil
}

// CanAccessAsset checks if a user can access a specific asset.
func (r *AccessControlRepository) CanAccessAsset(ctx context.Context, userID, assetID shared.ID) (bool, error) {
	// First try materialized view (fast)
	query := `
		SELECT EXISTS(
			SELECT 1 FROM user_accessible_assets
			WHERE user_id = $1 AND asset_id = $2
		)
	`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, userID.String(), assetID.String()).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check asset access: %w", err)
	}

	return exists, nil
}

// HasAnyScopeAssignment checks if a user has any rows in user_accessible_assets.
// Returns true if the user has at least one group-based asset assignment.
// Used for backward compat: if false, user sees all data (no groups configured yet).
func (r *AccessControlRepository) HasAnyScopeAssignment(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM user_accessible_assets
			WHERE user_id = $1 AND tenant_id = $2
		)
	`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, userID.String(), tenantID.String()).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check scope assignment: %w", err)
	}

	return exists, nil
}

// GetUserAssetAccess gets the user's access details for an asset.
func (r *AccessControlRepository) GetUserAssetAccess(ctx context.Context, userID, assetID shared.ID) (*accesscontrol.UserAssetAccess, error) {
	query := `
		SELECT
			uaa.user_id,
			uaa.asset_id,
			uaa.ownership_type,
			gm.group_id,
			g.name as group_name
		FROM user_accessible_assets uaa
		JOIN group_members gm ON gm.user_id = uaa.user_id
		JOIN groups g ON g.id = gm.group_id AND g.is_active = true
		JOIN asset_owners ao ON ao.asset_id = uaa.asset_id AND ao.group_id = gm.group_id
		WHERE uaa.user_id = $1 AND uaa.asset_id = $2
		ORDER BY
			CASE uaa.ownership_type
				WHEN 'primary' THEN 1
				WHEN 'secondary' THEN 2
				WHEN 'stakeholder' THEN 3
				WHEN 'informed' THEN 4
			END
		LIMIT 1
	`

	var (
		userIDStr     string
		assetIDStr    string
		ownershipType string
		groupIDStr    string
		groupName     string
	)

	err := r.db.QueryRowContext(ctx, query, userID.String(), assetID.String()).Scan(
		&userIDStr,
		&assetIDStr,
		&ownershipType,
		&groupIDStr,
		&groupName,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, accesscontrol.ErrAssetAccessDenied
		}
		return nil, fmt.Errorf("failed to get user asset access: %w", err)
	}

	uid, err := shared.IDFromString(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user ID: %w", err)
	}

	aid, err := shared.IDFromString(assetIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse asset ID: %w", err)
	}

	gid, err := shared.IDFromString(groupIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse group ID: %w", err)
	}

	return &accesscontrol.UserAssetAccess{
		UserID:        uid,
		AssetID:       aid,
		OwnershipType: accesscontrol.OwnershipType(ownershipType),
		GroupID:       gid,
		GroupName:     groupName,
	}, nil
}

// =============================================================================
// GROUP PERMISSIONS
// =============================================================================

// CreateGroupPermission creates a new group permission override.
func (r *AccessControlRepository) CreateGroupPermission(ctx context.Context, gp *accesscontrol.GroupPermission) error {
	scopeTypeStr := sql.NullString{}
	if gp.ScopeType() != nil {
		scopeTypeStr = sql.NullString{String: gp.ScopeType().String(), Valid: true}
	}

	var scopeValue any
	if gp.ScopeValue() != nil {
		jsonBytes, err := json.Marshal(gp.ScopeValue())
		if err != nil {
			return fmt.Errorf("failed to marshal scope value: %w", err)
		}
		scopeValue = jsonBytes
	}

	var createdBy any
	if gp.CreatedBy() != nil {
		createdBy = gp.CreatedBy().String()
	}

	query := `
		INSERT INTO group_permissions (group_id, permission_id, effect, scope_type, scope_value, created_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (group_id, permission_id) DO NOTHING
	`

	result, err := r.db.ExecContext(ctx, query,
		gp.GroupID().String(),
		gp.PermissionID(),
		gp.Effect().String(),
		scopeTypeStr,
		scopeValue,
		gp.CreatedAt(),
		createdBy,
	)
	if err != nil {
		return fmt.Errorf("failed to create group permission: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return accesscontrol.ErrGroupPermissionExists
	}

	return nil
}

// GetGroupPermission retrieves a group permission by group ID and permission ID.
func (r *AccessControlRepository) GetGroupPermission(ctx context.Context, groupID shared.ID, permissionID string) (*accesscontrol.GroupPermission, error) {
	query := `
		SELECT group_id, permission_id, effect, scope_type, scope_value, created_at, created_by
		FROM group_permissions
		WHERE group_id = $1 AND permission_id = $2
	`

	var (
		groupIDStr   string
		permID       string
		effect       string
		scopeType    sql.NullString
		scopeValue   []byte
		createdAt    sql.NullTime
		createdByStr sql.NullString
	)

	err := r.db.QueryRowContext(ctx, query, groupID.String(), permissionID).Scan(
		&groupIDStr,
		&permID,
		&effect,
		&scopeType,
		&scopeValue,
		&createdAt,
		&createdByStr,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, accesscontrol.ErrGroupPermissionNotFound
		}
		return nil, fmt.Errorf("failed to get group permission: %w", err)
	}

	return r.scanGroupPermission(groupIDStr, permID, effect, scopeType, scopeValue, createdAt, createdByStr)
}

// UpdateGroupPermission updates an existing group permission.
func (r *AccessControlRepository) UpdateGroupPermission(ctx context.Context, gp *accesscontrol.GroupPermission) error {
	scopeTypeStr := sql.NullString{}
	if gp.ScopeType() != nil {
		scopeTypeStr = sql.NullString{String: gp.ScopeType().String(), Valid: true}
	}

	var scopeValue any
	if gp.ScopeValue() != nil {
		jsonBytes, err := json.Marshal(gp.ScopeValue())
		if err != nil {
			return fmt.Errorf("failed to marshal scope value: %w", err)
		}
		scopeValue = jsonBytes
	}

	query := `
		UPDATE group_permissions
		SET effect = $1, scope_type = $2, scope_value = $3
		WHERE group_id = $4 AND permission_id = $5
	`

	result, err := r.db.ExecContext(ctx, query,
		gp.Effect().String(),
		scopeTypeStr,
		scopeValue,
		gp.GroupID().String(),
		gp.PermissionID(),
	)
	if err != nil {
		return fmt.Errorf("failed to update group permission: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return accesscontrol.ErrGroupPermissionNotFound
	}

	return nil
}

// DeleteGroupPermission removes a group permission.
func (r *AccessControlRepository) DeleteGroupPermission(ctx context.Context, groupID shared.ID, permissionID string) error {
	query := `DELETE FROM group_permissions WHERE group_id = $1 AND permission_id = $2`

	result, err := r.db.ExecContext(ctx, query, groupID.String(), permissionID)
	if err != nil {
		return fmt.Errorf("failed to delete group permission: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return accesscontrol.ErrGroupPermissionNotFound
	}

	return nil
}

// ListGroupPermissions lists all custom permissions for a group.
func (r *AccessControlRepository) ListGroupPermissions(ctx context.Context, groupID shared.ID) ([]*accesscontrol.GroupPermission, error) {
	query := `
		SELECT group_id, permission_id, effect, scope_type, scope_value, created_at, created_by
		FROM group_permissions
		WHERE group_id = $1
		ORDER BY permission_id
	`

	rows, err := r.db.QueryContext(ctx, query, groupID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list group permissions: %w", err)
	}
	defer rows.Close()

	return r.scanGroupPermissions(rows)
}

// ListGroupPermissionsByEffect lists group permissions filtered by effect.
func (r *AccessControlRepository) ListGroupPermissionsByEffect(ctx context.Context, groupID shared.ID, effect accesscontrol.PermissionEffect) ([]*accesscontrol.GroupPermission, error) {
	query := `
		SELECT group_id, permission_id, effect, scope_type, scope_value, created_at, created_by
		FROM group_permissions
		WHERE group_id = $1 AND effect = $2
		ORDER BY permission_id
	`

	rows, err := r.db.QueryContext(ctx, query, groupID.String(), effect.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list group permissions by effect: %w", err)
	}
	defer rows.Close()

	return r.scanGroupPermissions(rows)
}

// scanGroupPermissions scans multiple rows into GroupPermission slice.
func (r *AccessControlRepository) scanGroupPermissions(rows *sql.Rows) ([]*accesscontrol.GroupPermission, error) {
	var permissions []*accesscontrol.GroupPermission
	for rows.Next() {
		var (
			groupIDStr   string
			permID       string
			effect       string
			scopeType    sql.NullString
			scopeValue   []byte
			createdAt    sql.NullTime
			createdByStr sql.NullString
		)

		if err := rows.Scan(&groupIDStr, &permID, &effect, &scopeType, &scopeValue, &createdAt, &createdByStr); err != nil {
			return nil, fmt.Errorf("failed to scan group permission: %w", err)
		}

		gp, err := r.scanGroupPermission(groupIDStr, permID, effect, scopeType, scopeValue, createdAt, createdByStr)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, gp)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating group permissions: %w", err)
	}

	return permissions, nil
}

// scanGroupPermission converts database values to a GroupPermission domain entity.
func (r *AccessControlRepository) scanGroupPermission(
	groupIDStr, permID, effect string,
	scopeType sql.NullString,
	scopeValue []byte,
	createdAt sql.NullTime,
	createdByStr sql.NullString,
) (*accesscontrol.GroupPermission, error) {
	groupID, err := shared.IDFromString(groupIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse group ID: %w", err)
	}

	var scopeTypePtr *accesscontrol.ScopeType
	if scopeType.Valid {
		st := accesscontrol.ScopeType(scopeType.String)
		scopeTypePtr = &st
	}

	var scopeValuePtr *accesscontrol.ScopeValue
	if len(scopeValue) > 0 {
		var sv accesscontrol.ScopeValue
		if err := json.Unmarshal(scopeValue, &sv); err != nil {
			return nil, fmt.Errorf("failed to unmarshal scope value: %w", err)
		}
		scopeValuePtr = &sv
	}

	var createdByID *shared.ID
	if createdByStr.Valid {
		id, err := shared.IDFromString(createdByStr.String)
		if err != nil {
			return nil, fmt.Errorf("failed to parse created_by ID: %w", err)
		}
		createdByID = &id
	}

	createdAtTime := createdAt.Time
	if !createdAt.Valid {
		createdAtTime = time.Now().UTC()
	}

	return accesscontrol.ReconstituteGroupPermission(
		groupID,
		permID,
		accesscontrol.PermissionEffect(effect),
		scopeTypePtr,
		scopeValuePtr,
		createdAtTime,
		createdByID,
	), nil
}

// =============================================================================
// ASSIGNMENT RULES
// =============================================================================

// CreateAssignmentRule creates a new assignment rule.
func (r *AccessControlRepository) CreateAssignmentRule(ctx context.Context, rule *accesscontrol.AssignmentRule) error {
	conditionsJSON, err := json.Marshal(rule.Conditions())
	if err != nil {
		return fmt.Errorf("failed to marshal conditions: %w", err)
	}

	optionsJSON, err := json.Marshal(rule.Options())
	if err != nil {
		return fmt.Errorf("failed to marshal options: %w", err)
	}

	var createdBy any
	if rule.CreatedBy() != nil {
		createdBy = rule.CreatedBy().String()
	}

	query := `
		INSERT INTO assignment_rules (
			id, tenant_id, name, description, priority, is_active,
			conditions, target_group_id, options, created_at, updated_at, created_by
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err = r.db.ExecContext(ctx, query,
		rule.ID().String(),
		rule.TenantID().String(),
		rule.Name(),
		rule.Description(),
		rule.Priority(),
		rule.IsActive(),
		conditionsJSON,
		rule.TargetGroupID().String(),
		optionsJSON,
		rule.CreatedAt(),
		rule.UpdatedAt(),
		createdBy,
	)
	if err != nil {
		return fmt.Errorf("failed to create assignment rule: %w", err)
	}

	return nil
}

// GetAssignmentRule retrieves an assignment rule by ID.
func (r *AccessControlRepository) GetAssignmentRule(ctx context.Context, tenantID, id shared.ID) (*accesscontrol.AssignmentRule, error) {
	query := `
		SELECT id, tenant_id, name, description, priority, is_active,
			   conditions, target_group_id, options, created_at, updated_at, created_by
		FROM assignment_rules
		WHERE id = $1 AND tenant_id = $2
	`

	var (
		idStr          string
		tenantIDStr    string
		name           string
		description    sql.NullString
		priority       int
		isActive       bool
		conditionsJSON []byte
		targetGroupStr string
		optionsJSON    []byte
		createdAt      sql.NullTime
		updatedAt      sql.NullTime
		createdByStr   sql.NullString
	)

	err := r.db.QueryRowContext(ctx, query, id.String(), tenantID.String()).Scan(
		&idStr,
		&tenantIDStr,
		&name,
		&description,
		&priority,
		&isActive,
		&conditionsJSON,
		&targetGroupStr,
		&optionsJSON,
		&createdAt,
		&updatedAt,
		&createdByStr,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, accesscontrol.ErrAssignmentRuleNotFound
		}
		return nil, fmt.Errorf("failed to get assignment rule: %w", err)
	}

	return r.scanAssignmentRule(
		idStr, tenantIDStr, name, description.String,
		priority, isActive, conditionsJSON, targetGroupStr,
		optionsJSON, createdAt, updatedAt, createdByStr,
	)
}

// UpdateAssignmentRule updates an existing assignment rule.
func (r *AccessControlRepository) UpdateAssignmentRule(ctx context.Context, tenantID shared.ID, rule *accesscontrol.AssignmentRule) error {
	conditionsJSON, err := json.Marshal(rule.Conditions())
	if err != nil {
		return fmt.Errorf("failed to marshal conditions: %w", err)
	}

	optionsJSON, err := json.Marshal(rule.Options())
	if err != nil {
		return fmt.Errorf("failed to marshal options: %w", err)
	}

	query := `
		UPDATE assignment_rules
		SET name = $1, description = $2, priority = $3, is_active = $4,
			conditions = $5, target_group_id = $6, options = $7, updated_at = $8
		WHERE id = $9 AND tenant_id = $10
	`

	result, err := r.db.ExecContext(ctx, query,
		rule.Name(),
		rule.Description(),
		rule.Priority(),
		rule.IsActive(),
		conditionsJSON,
		rule.TargetGroupID().String(),
		optionsJSON,
		rule.UpdatedAt(),
		rule.ID().String(),
		tenantID.String(),
	)
	if err != nil {
		return fmt.Errorf("failed to update assignment rule: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return accesscontrol.ErrAssignmentRuleNotFound
	}

	return nil
}

// DeleteAssignmentRule removes an assignment rule.
func (r *AccessControlRepository) DeleteAssignmentRule(ctx context.Context, tenantID, id shared.ID) error {
	query := `DELETE FROM assignment_rules WHERE id = $1 AND tenant_id = $2`

	result, err := r.db.ExecContext(ctx, query, id.String(), tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to delete assignment rule: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return accesscontrol.ErrAssignmentRuleNotFound
	}

	return nil
}

// ListAssignmentRules lists assignment rules with filtering.
func (r *AccessControlRepository) ListAssignmentRules(ctx context.Context, tenantID shared.ID, filter accesscontrol.AssignmentRuleFilter) ([]*accesscontrol.AssignmentRule, error) {
	query := `
		SELECT id, tenant_id, name, description, priority, is_active,
			   conditions, target_group_id, options, created_at, updated_at, created_by
		FROM assignment_rules
		WHERE tenant_id = $1
	`
	args := []any{tenantID.String()}
	argIdx := 2

	if filter.IsActive != nil {
		query += fmt.Sprintf(" AND is_active = $%d", argIdx)
		args = append(args, *filter.IsActive)
		argIdx++
	}

	if filter.TargetGroupID != nil {
		query += fmt.Sprintf(" AND target_group_id = $%d", argIdx)
		args = append(args, filter.TargetGroupID.String())
		argIdx++
	}

	if filter.Search != "" {
		query += fmt.Sprintf(" AND (name ILIKE $%d OR description ILIKE $%d)", argIdx, argIdx)
		args = append(args, wrapLikePattern(filter.Search))
		argIdx++
	}

	// Sorting
	orderBy := sortFieldPriority
	switch filter.OrderBy {
	case sortFieldName:
		orderBy = sortFieldName
	case sortFieldCreatedAt:
		orderBy = sortFieldCreatedAt
	case sortFieldPriority:
		orderBy = sortFieldPriority
	}
	orderDir := sortOrderASC
	if filter.OrderDesc {
		orderDir = sortOrderDESC
	}
	query += fmt.Sprintf(" ORDER BY %s %s", orderBy, orderDir)

	// Pagination
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, filter.Limit)
		argIdx++
	}
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, filter.Offset)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list assignment rules: %w", err)
	}
	defer rows.Close()

	return r.scanAssignmentRules(rows)
}

// CountAssignmentRules counts assignment rules with filtering.
func (r *AccessControlRepository) CountAssignmentRules(ctx context.Context, tenantID shared.ID, filter accesscontrol.AssignmentRuleFilter) (int64, error) {
	query := `
		SELECT COUNT(*)
		FROM assignment_rules
		WHERE tenant_id = $1
	`
	args := []any{tenantID.String()}
	argIdx := 2

	if filter.IsActive != nil {
		query += fmt.Sprintf(" AND is_active = $%d", argIdx)
		args = append(args, *filter.IsActive)
		argIdx++
	}

	if filter.TargetGroupID != nil {
		query += fmt.Sprintf(" AND target_group_id = $%d", argIdx)
		args = append(args, filter.TargetGroupID.String())
		argIdx++
	}

	if filter.Search != "" {
		query += fmt.Sprintf(" AND (name ILIKE $%d OR description ILIKE $%d)", argIdx, argIdx)
		args = append(args, wrapLikePattern(filter.Search))
	}

	var count int64
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count assignment rules: %w", err)
	}

	return count, nil
}

// ListActiveRulesByPriority lists active assignment rules ordered by priority (descending).
func (r *AccessControlRepository) ListActiveRulesByPriority(ctx context.Context, tenantID shared.ID) ([]*accesscontrol.AssignmentRule, error) {
	query := `
		SELECT id, tenant_id, name, description, priority, is_active,
			   conditions, target_group_id, options, created_at, updated_at, created_by
		FROM assignment_rules
		WHERE tenant_id = $1 AND is_active = true
		ORDER BY priority DESC, created_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list active rules by priority: %w", err)
	}
	defer rows.Close()

	return r.scanAssignmentRules(rows)
}

// scanAssignmentRules scans multiple rows into AssignmentRule slice.
func (r *AccessControlRepository) scanAssignmentRules(rows *sql.Rows) ([]*accesscontrol.AssignmentRule, error) {
	var rules []*accesscontrol.AssignmentRule
	for rows.Next() {
		var (
			idStr          string
			tenantIDStr    string
			name           string
			description    sql.NullString
			priority       int
			isActive       bool
			conditionsJSON []byte
			targetGroupStr string
			optionsJSON    []byte
			createdAt      sql.NullTime
			updatedAt      sql.NullTime
			createdByStr   sql.NullString
		)

		if err := rows.Scan(
			&idStr, &tenantIDStr, &name, &description, &priority, &isActive,
			&conditionsJSON, &targetGroupStr, &optionsJSON, &createdAt, &updatedAt, &createdByStr,
		); err != nil {
			return nil, fmt.Errorf("failed to scan assignment rule: %w", err)
		}

		rule, err := r.scanAssignmentRule(
			idStr, tenantIDStr, name, description.String,
			priority, isActive, conditionsJSON, targetGroupStr,
			optionsJSON, createdAt, updatedAt, createdByStr,
		)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating assignment rules: %w", err)
	}

	return rules, nil
}

// scanAssignmentRule converts database values to an AssignmentRule domain entity.
func (r *AccessControlRepository) scanAssignmentRule(
	idStr, tenantIDStr, name, description string,
	priority int, isActive bool,
	conditionsJSON []byte, targetGroupStr string,
	optionsJSON []byte,
	createdAt, updatedAt sql.NullTime,
	createdByStr sql.NullString,
) (*accesscontrol.AssignmentRule, error) {
	id, err := shared.IDFromString(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rule ID: %w", err)
	}

	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tenant ID: %w", err)
	}

	targetGroupID, err := shared.IDFromString(targetGroupStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target group ID: %w", err)
	}

	var conditions accesscontrol.AssignmentConditions
	if len(conditionsJSON) > 0 {
		if err := json.Unmarshal(conditionsJSON, &conditions); err != nil {
			return nil, fmt.Errorf("failed to unmarshal conditions: %w", err)
		}
	}

	var options accesscontrol.AssignmentOptions
	if len(optionsJSON) > 0 {
		if err := json.Unmarshal(optionsJSON, &options); err != nil {
			return nil, fmt.Errorf("failed to unmarshal options: %w", err)
		}
	}

	var createdByID *shared.ID
	if createdByStr.Valid {
		cbID, err := shared.IDFromString(createdByStr.String)
		if err != nil {
			return nil, fmt.Errorf("failed to parse created_by ID: %w", err)
		}
		createdByID = &cbID
	}

	createdAtTime := createdAt.Time
	if !createdAt.Valid {
		createdAtTime = time.Now().UTC()
	}

	updatedAtTime := updatedAt.Time
	if !updatedAt.Valid {
		updatedAtTime = createdAtTime
	}

	return accesscontrol.ReconstituteAssignmentRule(
		id,
		tenantID,
		name,
		description,
		priority,
		isActive,
		conditions,
		targetGroupID,
		options,
		createdAtTime,
		updatedAtTime,
		createdByID,
	), nil
}

// =============================================================================
// BULK OPERATIONS
// =============================================================================

// BulkCreateAssetOwners inserts multiple asset owners in batches.
// Returns the number of rows successfully inserted.
func (r *AccessControlRepository) BulkCreateAssetOwners(ctx context.Context, owners []*accesscontrol.AssetOwner) (int, error) {
	if len(owners) == 0 {
		return 0, nil
	}

	const batchSize = 500
	totalInserted := 0

	for i := 0; i < len(owners); i += batchSize {
		end := min(i+batchSize, len(owners))
		batch := owners[i:end]

		var sb strings.Builder
		sb.WriteString(`INSERT INTO asset_owners (id, asset_id, group_id, user_id, ownership_type, assigned_at, assigned_by) VALUES `)
		args := make([]any, 0, len(batch)*7)
		argIdx := 1

		for j, ao := range batch {
			if j > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d, $%d)",
				argIdx, argIdx+1, argIdx+2, argIdx+3, argIdx+4, argIdx+5, argIdx+6))
			argIdx += 7

			var groupID, userID, assignedBy any
			if ao.GroupID() != nil {
				groupID = ao.GroupID().String()
			}
			if ao.UserID() != nil {
				userID = ao.UserID().String()
			}
			if ao.AssignedBy() != nil {
				assignedBy = ao.AssignedBy().String()
			}

			args = append(args,
				ao.ID().String(),
				ao.AssetID().String(),
				groupID,
				userID,
				ao.OwnershipType().String(),
				ao.AssignedAt(),
				assignedBy,
			)
		}

		sb.WriteString(" ON CONFLICT DO NOTHING")

		result, err := r.db.ExecContext(ctx, sb.String(), args...)
		if err != nil {
			return totalInserted, fmt.Errorf("failed to bulk create asset owners (batch %d): %w", i/batchSize, err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return totalInserted, fmt.Errorf("failed to get rows affected: %w", err)
		}
		totalInserted += int(rowsAffected)
	}

	return totalInserted, nil
}

// =============================================================================
// MATERIALIZED VIEW OPERATIONS
// =============================================================================

// RefreshUserAccessibleAssets refreshes the materialized view for user-asset access.
func (r *AccessControlRepository) RefreshUserAccessibleAssets(ctx context.Context) error {
	query := `SELECT refresh_user_accessible_assets()`

	_, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to refresh user accessible assets: %w", err)
	}

	return nil
}

// =============================================================================
// INCREMENTAL ACCESS REFRESH
// =============================================================================

// RefreshAccessForAssetAssign incrementally updates access when an asset is assigned to a group.
func (r *AccessControlRepository) RefreshAccessForAssetAssign(ctx context.Context, groupID, assetID shared.ID, ownershipType string) error {
	query := `SELECT refresh_access_for_asset_assign($1, $2, $3)`
	_, err := r.db.ExecContext(ctx, query, groupID.String(), assetID.String(), ownershipType)
	if err != nil {
		return fmt.Errorf("failed to refresh access for asset assign: %w", err)
	}
	return nil
}

// RefreshAccessForAssetUnassign incrementally updates access when an asset is removed from a group.
func (r *AccessControlRepository) RefreshAccessForAssetUnassign(ctx context.Context, groupID, assetID shared.ID) error {
	query := `SELECT refresh_access_for_asset_unassign($1, $2)`
	_, err := r.db.ExecContext(ctx, query, groupID.String(), assetID.String())
	if err != nil {
		return fmt.Errorf("failed to refresh access for asset unassign: %w", err)
	}
	return nil
}

// RefreshAccessForMemberAdd incrementally updates access when a user is added to a group.
func (r *AccessControlRepository) RefreshAccessForMemberAdd(ctx context.Context, groupID, userID shared.ID) error {
	query := `SELECT refresh_access_for_member_add($1, $2)`
	_, err := r.db.ExecContext(ctx, query, groupID.String(), userID.String())
	if err != nil {
		return fmt.Errorf("failed to refresh access for member add: %w", err)
	}
	return nil
}

// RefreshAccessForMemberRemove incrementally updates access when a user is removed from a group.
func (r *AccessControlRepository) RefreshAccessForMemberRemove(ctx context.Context, groupID, userID shared.ID) error {
	query := `SELECT refresh_access_for_member_remove($1, $2)`
	_, err := r.db.ExecContext(ctx, query, groupID.String(), userID.String())
	if err != nil {
		return fmt.Errorf("failed to refresh access for member remove: %w", err)
	}
	return nil
}

// =============================================================================
// SCOPE RULES
// =============================================================================

// CreateScopeRule creates a new scope rule.
func (r *AccessControlRepository) CreateScopeRule(ctx context.Context, rule *accesscontrol.ScopeRule) error {
	query := `
		INSERT INTO group_asset_scope_rules
			(id, tenant_id, group_id, name, description, rule_type, match_tags, match_logic,
			 match_asset_group_ids, ownership_type, priority, is_active, created_at, updated_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`
	var createdBy any
	if rule.CreatedBy() != nil {
		createdBy = rule.CreatedBy().String()
	}

	matchAssetGroupIDs := make([]string, 0, len(rule.MatchAssetGroupIDs()))
	for _, id := range rule.MatchAssetGroupIDs() {
		matchAssetGroupIDs = append(matchAssetGroupIDs, id.String())
	}

	_, err := r.db.ExecContext(ctx, query,
		rule.ID().String(),
		rule.TenantID().String(),
		rule.GroupID().String(),
		rule.Name(),
		rule.Description(),
		rule.RuleType().String(),
		rule.MatchTags(),
		string(rule.MatchLogic()),
		matchAssetGroupIDs,
		rule.OwnershipType().String(),
		rule.Priority(),
		rule.IsActive(),
		rule.CreatedAt(),
		rule.UpdatedAt(),
		createdBy,
	)
	if err != nil {
		return fmt.Errorf("failed to create scope rule: %w", err)
	}
	return nil
}

// GetScopeRule retrieves a scope rule by ID with tenant isolation.
func (r *AccessControlRepository) GetScopeRule(ctx context.Context, tenantID, id shared.ID) (*accesscontrol.ScopeRule, error) {
	query := `
		SELECT id, tenant_id, group_id, name, description, rule_type, match_tags, match_logic,
			   match_asset_group_ids, ownership_type, priority, is_active, created_at, updated_at, created_by
		FROM group_asset_scope_rules
		WHERE id = $1 AND tenant_id = $2
	`
	row := r.db.QueryRowContext(ctx, query, id.String(), tenantID.String())
	return r.scanScopeRule(row)
}

// UpdateScopeRule updates an existing scope rule with tenant isolation.
func (r *AccessControlRepository) UpdateScopeRule(ctx context.Context, tenantID shared.ID, rule *accesscontrol.ScopeRule) error {
	matchAssetGroupIDs := make([]string, 0, len(rule.MatchAssetGroupIDs()))
	for _, id := range rule.MatchAssetGroupIDs() {
		matchAssetGroupIDs = append(matchAssetGroupIDs, id.String())
	}

	query := `
		UPDATE group_asset_scope_rules
		SET name = $3, description = $4, match_tags = $5, match_logic = $6,
			match_asset_group_ids = $7, ownership_type = $8, priority = $9,
			is_active = $10, updated_at = $11
		WHERE id = $1 AND tenant_id = $2
	`
	result, err := r.db.ExecContext(ctx, query,
		rule.ID().String(),
		tenantID.String(),
		rule.Name(),
		rule.Description(),
		rule.MatchTags(),
		string(rule.MatchLogic()),
		matchAssetGroupIDs,
		rule.OwnershipType().String(),
		rule.Priority(),
		rule.IsActive(),
		rule.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to update scope rule: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}
	return nil
}

// DeleteScopeRule deletes a scope rule by ID with tenant isolation.
func (r *AccessControlRepository) DeleteScopeRule(ctx context.Context, tenantID, id shared.ID) error {
	query := `DELETE FROM group_asset_scope_rules WHERE id = $1 AND tenant_id = $2`
	result, err := r.db.ExecContext(ctx, query, id.String(), tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to delete scope rule: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}
	return nil
}

// ListScopeRules lists scope rules for a group.
func (r *AccessControlRepository) ListScopeRules(ctx context.Context, tenantID, groupID shared.ID, filter accesscontrol.ScopeRuleFilter) ([]*accesscontrol.ScopeRule, error) {
	query := `
		SELECT id, tenant_id, group_id, name, description, rule_type, match_tags, match_logic,
			   match_asset_group_ids, ownership_type, priority, is_active, created_at, updated_at, created_by
		FROM group_asset_scope_rules
		WHERE group_id = $1 AND tenant_id = $2
	`
	args := []any{groupID.String(), tenantID.String()}
	argIdx := 3

	if filter.IsActive != nil {
		query += fmt.Sprintf(" AND is_active = $%d", argIdx)
		args = append(args, *filter.IsActive)
		argIdx++
	}

	query += " ORDER BY priority DESC, created_at ASC"

	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, filter.Limit)
		argIdx++
	}
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, filter.Offset)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list scope rules: %w", err)
	}
	defer rows.Close()

	return r.scanScopeRules(rows)
}

// CountScopeRules counts scope rules for a group with tenant isolation, respecting the same filter as ListScopeRules.
func (r *AccessControlRepository) CountScopeRules(ctx context.Context, tenantID, groupID shared.ID, filter accesscontrol.ScopeRuleFilter) (int64, error) {
	query := `SELECT COUNT(*) FROM group_asset_scope_rules WHERE group_id = $1 AND tenant_id = $2`
	args := []any{groupID.String(), tenantID.String()}
	argIdx := 3

	if filter.IsActive != nil {
		query += fmt.Sprintf(" AND is_active = $%d", argIdx)
		args = append(args, *filter.IsActive)
	}

	var count int64
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count scope rules: %w", err)
	}
	return count, nil
}

// ListActiveScopeRulesByTenant returns all active scope rules for a tenant.
func (r *AccessControlRepository) ListActiveScopeRulesByTenant(ctx context.Context, tenantID shared.ID) ([]*accesscontrol.ScopeRule, error) {
	query := `
		SELECT id, tenant_id, group_id, name, description, rule_type, match_tags, match_logic,
			   match_asset_group_ids, ownership_type, priority, is_active, created_at, updated_at, created_by
		FROM group_asset_scope_rules
		WHERE tenant_id = $1 AND is_active = TRUE
		ORDER BY priority DESC, created_at ASC
	`
	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list active scope rules by tenant: %w", err)
	}
	defer rows.Close()

	return r.scanScopeRules(rows)
}

// ListActiveScopeRulesByGroup returns all active scope rules for a group with tenant isolation.
func (r *AccessControlRepository) ListActiveScopeRulesByGroup(ctx context.Context, tenantID, groupID shared.ID) ([]*accesscontrol.ScopeRule, error) {
	query := `
		SELECT id, tenant_id, group_id, name, description, rule_type, match_tags, match_logic,
			   match_asset_group_ids, ownership_type, priority, is_active, created_at, updated_at, created_by
		FROM group_asset_scope_rules
		WHERE group_id = $1 AND tenant_id = $2 AND is_active = TRUE
		ORDER BY priority DESC, created_at ASC
	`
	rows, err := r.db.QueryContext(ctx, query, groupID.String(), tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list active scope rules by group: %w", err)
	}
	defer rows.Close()

	return r.scanScopeRules(rows)
}

// CreateAssetOwnerWithSource creates an asset owner record with source tracking.
func (r *AccessControlRepository) CreateAssetOwnerWithSource(ctx context.Context, ao *accesscontrol.AssetOwner, source string, ruleID *shared.ID) error {
	query := `
		INSERT INTO asset_owners (id, asset_id, group_id, user_id, ownership_type, assigned_at, assigned_by, assignment_source, scope_rule_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT DO NOTHING
	`
	var groupID, userID, assignedBy, ruleIDVal any
	if ao.GroupID() != nil {
		groupID = ao.GroupID().String()
	}
	if ao.UserID() != nil {
		userID = ao.UserID().String()
	}
	if ao.AssignedBy() != nil {
		assignedBy = ao.AssignedBy().String()
	}
	if ruleID != nil {
		ruleIDVal = ruleID.String()
	}

	_, err := r.db.ExecContext(ctx, query,
		ao.ID().String(),
		ao.AssetID().String(),
		groupID,
		userID,
		ao.OwnershipType().String(),
		ao.AssignedAt(),
		assignedBy,
		source,
		ruleIDVal,
	)
	if err != nil {
		return fmt.Errorf("failed to create asset owner with source: %w", err)
	}
	return nil
}

// bulkCreateSourceChunkSize limits each INSERT batch to stay within PostgreSQL's 65535
// parameter limit. With 9 params per row: 65535/9 = 7281 rows max per chunk.
const bulkCreateSourceChunkSize = 5000

// BulkCreateAssetOwnersWithSource creates multiple asset owner records with source tracking.
// Automatically chunks large batches to stay within PostgreSQL parameter limits.
func (r *AccessControlRepository) BulkCreateAssetOwnersWithSource(ctx context.Context, owners []*accesscontrol.AssetOwner, source string, ruleID *shared.ID) (int, error) {
	if len(owners) == 0 {
		return 0, nil
	}
	const maxBulkSize = 50000
	if len(owners) > maxBulkSize {
		return 0, fmt.Errorf("batch size %d exceeds maximum of %d", len(owners), maxBulkSize)
	}

	totalAdded := 0
	for start := 0; start < len(owners); start += bulkCreateSourceChunkSize {
		end := min(start+bulkCreateSourceChunkSize, len(owners))
		chunk := owners[start:end]

		added, err := r.bulkCreateAssetOwnersWithSourceChunk(ctx, chunk, source, ruleID)
		if err != nil {
			return totalAdded, err
		}
		totalAdded += added
	}
	return totalAdded, nil
}

func (r *AccessControlRepository) bulkCreateAssetOwnersWithSourceChunk(ctx context.Context, owners []*accesscontrol.AssetOwner, source string, ruleID *shared.ID) (int, error) {
	var sb strings.Builder
	sb.WriteString(`INSERT INTO asset_owners (id, asset_id, group_id, user_id, ownership_type, assigned_at, assigned_by, assignment_source, scope_rule_id) VALUES `)
	args := make([]any, 0, len(owners)*9)
	argIdx := 1

	for i, ao := range owners {
		if i > 0 {
			sb.WriteString(", ")
		}
		fmt.Fprintf(&sb, "($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			argIdx, argIdx+1, argIdx+2, argIdx+3, argIdx+4, argIdx+5, argIdx+6, argIdx+7, argIdx+8)

		var groupID, userID, assignedBy, ruleIDVal any
		if ao.GroupID() != nil {
			groupID = ao.GroupID().String()
		}
		if ao.UserID() != nil {
			userID = ao.UserID().String()
		}
		if ao.AssignedBy() != nil {
			assignedBy = ao.AssignedBy().String()
		}
		if ruleID != nil {
			ruleIDVal = ruleID.String()
		}

		args = append(args, ao.ID().String(), ao.AssetID().String(), groupID, userID,
			ao.OwnershipType().String(), ao.AssignedAt(), assignedBy, source, ruleIDVal)
		argIdx += 9
	}

	sb.WriteString(" ON CONFLICT DO NOTHING")

	result, err := r.db.ExecContext(ctx, sb.String(), args...)
	if err != nil {
		return 0, fmt.Errorf("failed to bulk create asset owners: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}
	return int(count), nil
}

// DeleteAutoAssignedByRule removes all auto-assigned asset owners created by a specific rule.
// Uses subquery to enforce tenant isolation via the scope rule's tenant.
func (r *AccessControlRepository) DeleteAutoAssignedByRule(ctx context.Context, tenantID, ruleID shared.ID) (int, error) {
	query := `
		DELETE FROM asset_owners
		WHERE scope_rule_id = $1
		AND assignment_source = 'scope_rule'
		AND scope_rule_id IN (SELECT id FROM group_asset_scope_rules WHERE tenant_id = $2)
	`
	result, err := r.db.ExecContext(ctx, query, ruleID.String(), tenantID.String())
	if err != nil {
		return 0, fmt.Errorf("failed to delete auto-assigned by rule: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}
	return int(count), nil
}

// DeleteAutoAssignedForAsset removes auto-assigned ownership for an asset in a specific group.
func (r *AccessControlRepository) DeleteAutoAssignedForAsset(ctx context.Context, assetID, groupID shared.ID) error {
	query := `DELETE FROM asset_owners WHERE asset_id = $1 AND group_id = $2 AND assignment_source = 'scope_rule'`
	_, err := r.db.ExecContext(ctx, query, assetID.String(), groupID.String())
	if err != nil {
		return fmt.Errorf("failed to delete auto-assigned for asset: %w", err)
	}
	return nil
}

// bulkDeleteChunkSize limits each DELETE IN (...) batch to stay well within PostgreSQL's
// 65535 parameter limit. Each chunk uses N+1 params (N asset IDs + 1 group ID).
const bulkDeleteChunkSize = 1000

// BulkDeleteAutoAssignedForAssets removes auto-assigned ownership for multiple assets in a group.
// Processes in chunks to avoid exceeding PostgreSQL's parameter limit.
func (r *AccessControlRepository) BulkDeleteAutoAssignedForAssets(ctx context.Context, assetIDs []shared.ID, groupID shared.ID) (int, error) {
	if len(assetIDs) == 0 {
		return 0, nil
	}

	totalRemoved := 0
	for start := 0; start < len(assetIDs); start += bulkDeleteChunkSize {
		end := min(start+bulkDeleteChunkSize, len(assetIDs))
		chunk := assetIDs[start:end]

		placeholders := make([]string, len(chunk))
		args := make([]any, 0, len(chunk)+1)
		for i, id := range chunk {
			placeholders[i] = fmt.Sprintf("$%d", i+1)
			args = append(args, id.String())
		}
		args = append(args, groupID.String())
		query := fmt.Sprintf(
			`DELETE FROM asset_owners WHERE asset_id IN (%s) AND group_id = $%d AND assignment_source = 'scope_rule'`,
			strings.Join(placeholders, ","),
			len(chunk)+1,
		)
		result, err := r.db.ExecContext(ctx, query, args...)
		if err != nil {
			return totalRemoved, fmt.Errorf("failed to bulk delete auto-assigned assets: %w", err)
		}
		rows, _ := result.RowsAffected()
		totalRemoved += int(rows)
	}

	return totalRemoved, nil
}

// ListAutoAssignedAssets lists asset IDs that are auto-assigned to a group via scope rules.
// Uses JOIN to enforce tenant isolation through the scope rule.
func (r *AccessControlRepository) ListAutoAssignedAssets(ctx context.Context, tenantID, groupID shared.ID) ([]shared.ID, error) {
	query := `
		SELECT ao.asset_id FROM asset_owners ao
		JOIN group_asset_scope_rules gasr ON gasr.id = ao.scope_rule_id
		WHERE ao.group_id = $1 AND gasr.tenant_id = $2 AND ao.assignment_source = 'scope_rule'
	`
	rows, err := r.db.QueryContext(ctx, query, groupID.String(), tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list auto-assigned assets: %w", err)
	}
	defer rows.Close()

	var ids []shared.ID
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return nil, fmt.Errorf("failed to scan asset id: %w", err)
		}
		id, err := shared.IDFromString(idStr)
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate auto-assigned assets: %w", err)
	}
	return ids, nil
}

// ListAutoAssignedGroupsForAsset lists group IDs that an asset is auto-assigned to via scope rules.
func (r *AccessControlRepository) ListAutoAssignedGroupsForAsset(ctx context.Context, assetID shared.ID) ([]shared.ID, error) {
	query := `SELECT DISTINCT group_id FROM asset_owners WHERE asset_id = $1 AND assignment_source = 'scope_rule'`
	rows, err := r.db.QueryContext(ctx, query, assetID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list auto-assigned groups for asset: %w", err)
	}
	defer rows.Close()

	var ids []shared.ID
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return nil, fmt.Errorf("failed to scan group id: %w", err)
		}
		id, err := shared.IDFromString(idStr)
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate auto-assigned groups: %w", err)
	}
	return ids, nil
}

// DeleteScopeRuleWithCleanup atomically removes auto-assigned assets and deletes the scope rule
// within a single transaction. This prevents the inconsistent state where assets are unassigned
// but the rule still exists (if rule deletion fails).
func (r *AccessControlRepository) DeleteScopeRuleWithCleanup(ctx context.Context, tenantID, ruleID shared.ID) (int, error) {
	var removed int
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		// Step 1: Delete auto-assigned asset owners created by this rule
		deleteOwnersQuery := `
			DELETE FROM asset_owners
			WHERE scope_rule_id = $1
			AND assignment_source = 'scope_rule'
			AND scope_rule_id IN (SELECT id FROM group_asset_scope_rules WHERE tenant_id = $2)
		`
		result, err := tx.ExecContext(ctx, deleteOwnersQuery, ruleID.String(), tenantID.String())
		if err != nil {
			return fmt.Errorf("failed to delete auto-assigned by rule: %w", err)
		}
		count, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		removed = int(count)

		// Step 2: Delete the scope rule itself
		deleteRuleQuery := `DELETE FROM group_asset_scope_rules WHERE id = $1 AND tenant_id = $2`
		ruleResult, err := tx.ExecContext(ctx, deleteRuleQuery, ruleID.String(), tenantID.String())
		if err != nil {
			return fmt.Errorf("failed to delete scope rule: %w", err)
		}
		ruleRows, _ := ruleResult.RowsAffected()
		if ruleRows == 0 {
			return fmt.Errorf("scope rule not found")
		}

		return nil
	})
	if err != nil {
		return 0, err
	}
	return removed, nil
}

// maxMatchingAssets is the safety limit for asset matching queries to prevent
// unbounded memory usage and excessive DB load during reconciliation.
const maxMatchingAssets = 50000

// FindAssetsByTagMatch finds assets matching tag criteria.
func (r *AccessControlRepository) FindAssetsByTagMatch(ctx context.Context, tenantID shared.ID, tags []string, logic accesscontrol.MatchLogic) ([]shared.ID, error) {
	var query string
	if logic == accesscontrol.MatchLogicAll {
		// AND: asset must have ALL tags
		query = `SELECT id FROM assets WHERE tenant_id = $1 AND tags @> $2 LIMIT ` + fmt.Sprintf("%d", maxMatchingAssets+1)
	} else {
		// OR: asset must have ANY tag
		query = `SELECT id FROM assets WHERE tenant_id = $1 AND tags && $2 LIMIT ` + fmt.Sprintf("%d", maxMatchingAssets+1)
	}

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), tags)
	if err != nil {
		return nil, fmt.Errorf("failed to find assets by tag match: %w", err)
	}
	defer rows.Close()

	var ids []shared.ID
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return nil, fmt.Errorf("failed to scan asset id: %w", err)
		}
		id, err := shared.IDFromString(idStr)
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate tag-matched assets: %w", err)
	}
	return ids, nil
}

// FindAssetsByAssetGroupMatch finds assets that belong to any of the specified asset groups.
func (r *AccessControlRepository) FindAssetsByAssetGroupMatch(ctx context.Context, tenantID shared.ID, assetGroupIDs []shared.ID) ([]shared.ID, error) {
	if len(assetGroupIDs) == 0 {
		return nil, nil
	}

	groupIDStrs := make([]string, 0, len(assetGroupIDs))
	for _, id := range assetGroupIDs {
		groupIDStrs = append(groupIDStrs, id.String())
	}

	query := fmt.Sprintf(`
		SELECT DISTINCT agm.asset_id
		FROM asset_group_members agm
		JOIN assets a ON a.id = agm.asset_id AND a.tenant_id = $1
		WHERE agm.asset_group_id = ANY($2)
		LIMIT %d
	`, maxMatchingAssets+1)
	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), groupIDStrs)
	if err != nil {
		return nil, fmt.Errorf("failed to find assets by asset group match: %w", err)
	}
	defer rows.Close()

	var ids []shared.ID
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return nil, fmt.Errorf("failed to scan asset id: %w", err)
		}
		id, err := shared.IDFromString(idStr)
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate asset-group-matched assets: %w", err)
	}
	return ids, nil
}

// scanScopeRule scans a single scope rule from a row.
func (r *AccessControlRepository) scanScopeRule(row *sql.Row) (*accesscontrol.ScopeRule, error) {
	var (
		idStr, tenantIDStr, groupIDStr string
		name, description              string
		ruleType, matchLogic           string
		ownershipType                  string
		matchTags                      []string
		matchAssetGroupIDStrs          []string
		priority                       int
		isActive                       bool
		createdAt, updatedAt           time.Time
		createdByStr                   *string
	)

	err := row.Scan(
		&idStr, &tenantIDStr, &groupIDStr, &name, &description,
		&ruleType, pq.Array(&matchTags), &matchLogic, pq.Array(&matchAssetGroupIDStrs),
		&ownershipType, &priority, &isActive, &createdAt, &updatedAt, &createdByStr,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan scope rule: %w", err)
	}

	id, _ := shared.IDFromString(idStr)
	tenantID, _ := shared.IDFromString(tenantIDStr)
	groupID, _ := shared.IDFromString(groupIDStr)

	var createdBy *shared.ID
	if createdByStr != nil {
		cb, err := shared.IDFromString(*createdByStr)
		if err == nil {
			createdBy = &cb
		}
	}

	matchAssetGroupIDs := make([]shared.ID, 0, len(matchAssetGroupIDStrs))
	for _, s := range matchAssetGroupIDStrs {
		agID, err := shared.IDFromString(s)
		if err == nil {
			matchAssetGroupIDs = append(matchAssetGroupIDs, agID)
		}
	}

	if matchTags == nil {
		matchTags = []string{}
	}

	return accesscontrol.ReconstituteScopeRule(
		id, tenantID, groupID,
		name, description,
		accesscontrol.ScopeRuleType(ruleType),
		matchTags,
		accesscontrol.MatchLogic(matchLogic),
		matchAssetGroupIDs,
		accesscontrol.OwnershipType(ownershipType),
		priority, isActive,
		createdAt, updatedAt,
		createdBy,
	), nil
}

// scanScopeRules scans multiple scope rules from rows.
func (r *AccessControlRepository) scanScopeRules(rows *sql.Rows) ([]*accesscontrol.ScopeRule, error) {
	var rules []*accesscontrol.ScopeRule
	for rows.Next() {
		var (
			idStr, tenantIDStr, groupIDStr string
			name, description              string
			ruleType, matchLogic           string
			ownershipType                  string
			matchTags                      []string
			matchAssetGroupIDStrs          []string
			priority                       int
			isActive                       bool
			createdAt, updatedAt           time.Time
			createdByStr                   *string
		)

		err := rows.Scan(
			&idStr, &tenantIDStr, &groupIDStr, &name, &description,
			&ruleType, pq.Array(&matchTags), &matchLogic, pq.Array(&matchAssetGroupIDStrs),
			&ownershipType, &priority, &isActive, &createdAt, &updatedAt, &createdByStr,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan scope rule: %w", err)
		}

		id, _ := shared.IDFromString(idStr)
		tenantID, _ := shared.IDFromString(tenantIDStr)
		groupID, _ := shared.IDFromString(groupIDStr)

		var createdBy *shared.ID
		if createdByStr != nil {
			cb, err := shared.IDFromString(*createdByStr)
			if err == nil {
				createdBy = &cb
			}
		}

		matchAssetGroupIDs := make([]shared.ID, 0, len(matchAssetGroupIDStrs))
		for _, s := range matchAssetGroupIDStrs {
			agID, err := shared.IDFromString(s)
			if err == nil {
				matchAssetGroupIDs = append(matchAssetGroupIDs, agID)
			}
		}

		if matchTags == nil {
			matchTags = []string{}
		}

		rules = append(rules, accesscontrol.ReconstituteScopeRule(
			id, tenantID, groupID,
			name, description,
			accesscontrol.ScopeRuleType(ruleType),
			matchTags,
			accesscontrol.MatchLogic(matchLogic),
			matchAssetGroupIDs,
			accesscontrol.OwnershipType(ownershipType),
			priority, isActive,
			createdAt, updatedAt,
			createdBy,
		))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate scope rules: %w", err)
	}
	return rules, nil
}

// =============================================================================
// FINDING GROUP ASSIGNMENTS
// =============================================================================

// BulkCreateFindingGroupAssignments inserts multiple finding-group assignments.
// Uses ON CONFLICT DO NOTHING for idempotency (same finding+group pair is ignored).
func (r *AccessControlRepository) BulkCreateFindingGroupAssignments(ctx context.Context, fgas []*accesscontrol.FindingGroupAssignment) (int, error) {
	if len(fgas) == 0 {
		return 0, nil
	}
	const maxBulkSize = 10000
	if len(fgas) > maxBulkSize {
		return 0, fmt.Errorf("batch size %d exceeds maximum of %d", len(fgas), maxBulkSize)
	}

	// Build a single multi-row INSERT for all assignments
	var sb strings.Builder
	sb.WriteString("INSERT INTO finding_group_assignments (id, tenant_id, finding_id, group_id, rule_id, assigned_at) VALUES ")

	args := make([]any, 0, len(fgas)*6)
	for i, fga := range fgas {
		if i > 0 {
			sb.WriteString(", ")
		}
		paramBase := i * 6
		fmt.Fprintf(&sb, "($%d, $%d, $%d, $%d, $%d, $%d)",
			paramBase+1, paramBase+2, paramBase+3, paramBase+4, paramBase+5, paramBase+6)

		var ruleID any
		if fga.RuleID() != nil {
			ruleID = fga.RuleID().String()
		}
		args = append(args,
			fga.ID().String(),
			fga.TenantID().String(),
			fga.FindingID().String(),
			fga.GroupID().String(),
			ruleID,
			fga.AssignedAt(),
		)
	}
	sb.WriteString(" ON CONFLICT (finding_id, group_id) DO NOTHING")

	result, err := r.db.ExecContext(ctx, sb.String(), args...)
	if err != nil {
		return 0, fmt.Errorf("failed to bulk create finding group assignments: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return int(rowsAffected), nil
}

// ListFindingGroupAssignments lists all group assignments for a finding.
func (r *AccessControlRepository) ListFindingGroupAssignments(ctx context.Context, tenantID, findingID shared.ID) ([]*accesscontrol.FindingGroupAssignment, error) {
	query := `
		SELECT id, tenant_id, finding_id, group_id, rule_id, assigned_at
		FROM finding_group_assignments
		WHERE tenant_id = $1 AND finding_id = $2
		ORDER BY assigned_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), findingID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list finding group assignments: %w", err)
	}
	defer rows.Close()

	var results []*accesscontrol.FindingGroupAssignment
	for rows.Next() {
		var (
			idStr, tenantIDStr, findingIDStr, groupIDStr string
			ruleIDStr                                    sql.NullString
			assignedAt                                   time.Time
		)

		if err := rows.Scan(&idStr, &tenantIDStr, &findingIDStr, &groupIDStr, &ruleIDStr, &assignedAt); err != nil {
			return nil, fmt.Errorf("failed to scan finding group assignment: %w", err)
		}

		id, _ := shared.IDFromString(idStr)
		tid, _ := shared.IDFromString(tenantIDStr)
		fid, _ := shared.IDFromString(findingIDStr)
		gid, _ := shared.IDFromString(groupIDStr)

		var ruleID *shared.ID
		if ruleIDStr.Valid {
			rid, err := shared.IDFromString(ruleIDStr.String)
			if err == nil {
				ruleID = &rid
			}
		}

		results = append(results, accesscontrol.ReconstituteFindingGroupAssignment(
			id, tid, fid, gid, ruleID, assignedAt,
		))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating finding group assignments: %w", err)
	}

	return results, nil
}

// BatchListFindingGroupIDs returns group IDs for multiple findings in a single query.
// Avoids N+1 when checking group membership for bulk operations.
func (r *AccessControlRepository) BatchListFindingGroupIDs(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID) (map[shared.ID][]shared.ID, error) {
	result := make(map[shared.ID][]shared.ID, len(findingIDs))
	if len(findingIDs) == 0 {
		return result, nil
	}

	ids := make([]string, len(findingIDs))
	for i, id := range findingIDs {
		ids[i] = id.String()
	}

	query := `
		SELECT finding_id, group_id
		FROM finding_group_assignments
		WHERE tenant_id = $1 AND finding_id = ANY($2)
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("failed to batch list finding group IDs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var findingIDStr, groupIDStr string
		if err := rows.Scan(&findingIDStr, &groupIDStr); err != nil {
			return nil, fmt.Errorf("failed to scan finding group ID: %w", err)
		}
		fid, _ := shared.IDFromString(findingIDStr)
		gid, _ := shared.IDFromString(groupIDStr)
		result[fid] = append(result[fid], gid)
	}

	return result, rows.Err()
}

// CountFindingsByGroupFromRules counts findings assigned to a group via assignment rules.
func (r *AccessControlRepository) CountFindingsByGroupFromRules(ctx context.Context, tenantID, groupID shared.ID) (int64, error) {
	query := `
		SELECT COUNT(*)
		FROM finding_group_assignments
		WHERE tenant_id = $1 AND group_id = $2
	`

	var count int64
	err := r.db.QueryRowContext(ctx, query, tenantID.String(), groupID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count findings by group from rules: %w", err)
	}
	return count, nil
}

// ListAssetOwnersWithNames returns asset owners with resolved user/group names.
func (r *AccessControlRepository) ListAssetOwnersWithNames(ctx context.Context, tenantID, assetID shared.ID) ([]*accesscontrol.AssetOwnerWithNames, error) {
	// Note: users table has column `name`, not `display_name`. Previous version
	// referenced `ab.display_name` which doesn't exist → 500 on every call.
	query := `
		SELECT ao.id, ao.asset_id, ao.group_id, ao.user_id, ao.ownership_type,
		       ao.assigned_at, ao.assigned_by,
		       COALESCE(u.name, '') AS user_name,
		       COALESCE(u.email, '') AS user_email,
		       COALESCE(g.name, '') AS group_name,
		       COALESCE(ab.name, '') AS assigned_by_name
		FROM asset_owners ao
		LEFT JOIN users u ON ao.user_id = u.id
		LEFT JOIN groups g ON ao.group_id = g.id
		LEFT JOIN users ab ON ao.assigned_by = ab.id
		WHERE ao.asset_id = $1
		  AND (ao.group_id IS NULL OR ao.group_id IN (SELECT id FROM groups WHERE tenant_id = $2))
		  AND (ao.user_id IS NULL OR ao.user_id IN (SELECT id FROM tenant_members WHERE tenant_id = $2))
		ORDER BY ao.ownership_type = 'primary' DESC, ao.assigned_at ASC`

	rows, err := r.db.QueryContext(ctx, query, assetID.String(), tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list asset owners with names: %w", err)
	}
	defer rows.Close()

	var results []*accesscontrol.AssetOwnerWithNames
	for rows.Next() {
		var (
			idStr          string
			assetIDStr     string
			groupIDStr     sql.NullString
			userIDStr      sql.NullString
			ownershipType  string
			assignedAt     sql.NullTime
			assignedBy     sql.NullString
			userName       string
			userEmail      string
			groupName      string
			assignedByName string
		)
		if err := rows.Scan(&idStr, &assetIDStr, &groupIDStr, &userIDStr, &ownershipType,
			&assignedAt, &assignedBy,
			&userName, &userEmail, &groupName, &assignedByName); err != nil {
			return nil, fmt.Errorf("failed to scan asset owner with names: %w", err)
		}

		ao, err := r.scanAssetOwner(idStr, assetIDStr, groupIDStr, userIDStr, ownershipType, assignedAt, assignedBy)
		if err != nil {
			return nil, fmt.Errorf("failed to reconstitute asset owner: %w", err)
		}

		results = append(results, &accesscontrol.AssetOwnerWithNames{
			AssetOwner:     ao,
			UserName:       userName,
			UserEmail:      userEmail,
			GroupName:      groupName,
			AssignedByName: assignedByName,
		})
	}
	return results, nil
}

// GetPrimaryOwnerBrief returns a lightweight representation of the primary owner for an asset.
func (r *AccessControlRepository) GetPrimaryOwnerBrief(ctx context.Context, tenantID, assetID shared.ID) (*accesscontrol.OwnerBrief, error) {
	query := `
		SELECT
			CASE WHEN ao.user_id IS NOT NULL THEN ao.user_id::text ELSE ao.group_id::text END AS owner_id,
			CASE WHEN ao.user_id IS NOT NULL THEN 'user' ELSE 'group' END AS owner_type,
			CASE WHEN ao.user_id IS NOT NULL THEN COALESCE(u.name, '') ELSE COALESCE(g.name, '') END AS owner_name,
			CASE WHEN ao.user_id IS NOT NULL THEN COALESCE(u.email, '') ELSE '' END AS owner_email
		FROM asset_owners ao
		LEFT JOIN users u ON ao.user_id = u.id
		LEFT JOIN groups g ON ao.group_id = g.id
		WHERE ao.asset_id = $1
		  AND ao.ownership_type = 'primary'
		  AND (ao.group_id IS NULL OR ao.group_id IN (SELECT id FROM groups WHERE tenant_id = $2))
		  AND (ao.user_id IS NULL OR ao.user_id IN (SELECT id FROM tenant_members WHERE tenant_id = $2))
		LIMIT 1`

	var brief accesscontrol.OwnerBrief
	err := r.db.QueryRowContext(ctx, query, assetID.String(), tenantID.String()).Scan(
		&brief.ID, &brief.Type, &brief.Name, &brief.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get primary owner brief: %w", err)
	}
	return &brief, nil
}

// GetPrimaryOwnersByAssetIDs returns primary owners for multiple assets in a single query.
// Returns a map of assetID (string) → OwnerBrief.
func (r *AccessControlRepository) GetPrimaryOwnersByAssetIDs(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[string]*accesscontrol.OwnerBrief, error) {
	if len(assetIDs) == 0 {
		return make(map[string]*accesscontrol.OwnerBrief), nil
	}

	// Build IN clause
	ids := make([]string, len(assetIDs))
	for i, id := range assetIDs {
		ids[i] = id.String()
	}

	query := `
		SELECT DISTINCT ON (ao.asset_id)
			ao.asset_id::text,
			CASE WHEN ao.user_id IS NOT NULL THEN ao.user_id::text ELSE ao.group_id::text END AS owner_id,
			CASE WHEN ao.user_id IS NOT NULL THEN 'user' ELSE 'group' END AS owner_type,
			CASE WHEN ao.user_id IS NOT NULL THEN COALESCE(u.name, '') ELSE COALESCE(g.name, '') END AS owner_name,
			CASE WHEN ao.user_id IS NOT NULL THEN COALESCE(u.email, '') ELSE '' END AS owner_email
		FROM asset_owners ao
		LEFT JOIN users u ON ao.user_id = u.id
		LEFT JOIN groups g ON ao.group_id = g.id
		WHERE ao.asset_id = ANY($1)
		  AND ao.ownership_type = 'primary'
		  AND (ao.group_id IS NULL OR ao.group_id IN (SELECT id FROM groups WHERE tenant_id = $2))
		  AND (ao.user_id IS NULL OR ao.user_id IN (SELECT id FROM tenant_members WHERE tenant_id = $2))
		ORDER BY ao.asset_id, ao.assigned_at ASC`

	rows, err := r.db.QueryContext(ctx, query, pq.Array(ids), tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get primary owners by asset IDs: %w", err)
	}
	defer rows.Close()

	result := make(map[string]*accesscontrol.OwnerBrief, len(assetIDs))
	for rows.Next() {
		var assetIDStr string
		var brief accesscontrol.OwnerBrief
		if err := rows.Scan(&assetIDStr, &brief.ID, &brief.Type, &brief.Name, &brief.Email); err != nil {
			return nil, fmt.Errorf("failed to scan primary owner: %w", err)
		}
		result[assetIDStr] = &brief
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate primary owners: %w", err)
	}

	return result, nil
}

// RefreshAccessForDirectOwnerAdd updates the user_accessible_assets materialized view
// when a user is directly added as an asset owner.
func (r *AccessControlRepository) RefreshAccessForDirectOwnerAdd(ctx context.Context, assetID, userID shared.ID, ownershipType string) error {
	query := `SELECT refresh_access_for_direct_owner_add($1, $2, $3)`

	_, err := r.db.ExecContext(ctx, query, assetID.String(), userID.String(), ownershipType)
	if err != nil {
		return fmt.Errorf("failed to refresh access for direct owner add: %w", err)
	}
	return nil
}

// RefreshAccessForDirectOwnerRemove updates the user_accessible_assets materialized view
// when a user is removed as a direct asset owner.
func (r *AccessControlRepository) RefreshAccessForDirectOwnerRemove(ctx context.Context, assetID, userID shared.ID) error {
	query := `SELECT refresh_access_for_direct_owner_remove($1, $2)`

	_, err := r.db.ExecContext(ctx, query, assetID.String(), userID.String())
	if err != nil {
		return fmt.Errorf("failed to refresh access for direct owner remove: %w", err)
	}
	return nil
}

// ListTenantsWithActiveScopeRules returns all tenants that have at least one active scope rule.
func (r *AccessControlRepository) ListTenantsWithActiveScopeRules(ctx context.Context) ([]shared.ID, error) {
	query := `SELECT DISTINCT tenant_id FROM group_asset_scope_rules WHERE is_active = true`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list tenants with active scope rules: %w", err)
	}
	defer rows.Close()

	ids := make([]shared.ID, 0)
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return nil, fmt.Errorf("failed to scan tenant id: %w", err)
		}
		id, err := shared.IDFromString(idStr)
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ListGroupsWithActiveScopeRules returns distinct group IDs that have active scope rules for a tenant.
func (r *AccessControlRepository) ListGroupsWithActiveScopeRules(ctx context.Context, tenantID shared.ID) ([]shared.ID, error) {
	query := `SELECT DISTINCT group_id FROM group_asset_scope_rules WHERE tenant_id = $1 AND is_active = true`
	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list groups with active scope rules: %w", err)
	}
	defer rows.Close()

	ids := make([]shared.ID, 0)
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return nil, fmt.Errorf("failed to scan group id: %w", err)
		}
		id, err := shared.IDFromString(idStr)
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ListGroupsWithAssetGroupMatchRule returns distinct access control group IDs that have
// active scope rules referencing the given asset group ID in match_asset_group_ids.
func (r *AccessControlRepository) ListGroupsWithAssetGroupMatchRule(ctx context.Context, assetGroupID shared.ID) ([]shared.ID, error) {
	query := `
		SELECT DISTINCT group_id
		FROM group_asset_scope_rules
		WHERE $1::uuid = ANY(match_asset_group_ids) AND is_active = true
	`
	rows, err := r.db.QueryContext(ctx, query, assetGroupID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list groups with asset group match rule: %w", err)
	}
	defer rows.Close()

	ids := make([]shared.ID, 0)
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return nil, fmt.Errorf("failed to scan group id: %w", err)
		}
		id, err := shared.IDFromString(idStr)
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ValidateAssetGroupsBelongToTenant checks that all given asset group IDs belong to the specified tenant.
// Returns an error if any asset group doesn't exist or belongs to a different tenant.
func (r *AccessControlRepository) ValidateAssetGroupsBelongToTenant(ctx context.Context, tenantID shared.ID, assetGroupIDs []shared.ID) error {
	if len(assetGroupIDs) == 0 {
		return nil
	}

	// Build parameterized IN clause
	placeholders := make([]string, len(assetGroupIDs))
	args := make([]interface{}, 0, len(assetGroupIDs)+1)
	args = append(args, tenantID.String())
	for i, id := range assetGroupIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args = append(args, id.String())
	}

	query := fmt.Sprintf(`
		SELECT COUNT(*) FROM asset_groups
		WHERE tenant_id = $1 AND id IN (%s)
	`, strings.Join(placeholders, ","))

	var count int
	if err := r.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return fmt.Errorf("failed to validate asset groups: %w", err)
	}
	if count != len(assetGroupIDs) {
		return fmt.Errorf("%w: one or more asset groups are invalid or belong to a different tenant", shared.ErrValidation)
	}
	return nil
}

// Ensure AccessControlRepository implements accesscontrol.Repository.
var _ accesscontrol.Repository = (*AccessControlRepository)(nil)
