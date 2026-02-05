package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

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
func (r *AccessControlRepository) GetAssignmentRule(ctx context.Context, id shared.ID) (*accesscontrol.AssignmentRule, error) {
	query := `
		SELECT id, tenant_id, name, description, priority, is_active,
			   conditions, target_group_id, options, created_at, updated_at, created_by
		FROM assignment_rules
		WHERE id = $1
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

	err := r.db.QueryRowContext(ctx, query, id.String()).Scan(
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
func (r *AccessControlRepository) UpdateAssignmentRule(ctx context.Context, rule *accesscontrol.AssignmentRule) error {
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
		WHERE id = $9
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
func (r *AccessControlRepository) DeleteAssignmentRule(ctx context.Context, id shared.ID) error {
	query := `DELETE FROM assignment_rules WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id.String())
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

// Ensure AccessControlRepository implements accesscontrol.Repository.
var _ accesscontrol.Repository = (*AccessControlRepository)(nil)
