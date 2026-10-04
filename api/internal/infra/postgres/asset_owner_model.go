package postgres

// One asset owner model: asset_owners is the only owner store. Migration
// 000340 folded assets.owner_id into it as 'primary' rows with source
// 'owner_ref'; nothing reads the column any more. The helpers below are what every
// "who owns this asset" reader uses, so the definition lives in one place:
//
//   - the primary user owner of an asset is its earliest-assigned 'primary'
//     row naming a user (finding auto-assign, the "by owner" finding groups);
//   - a user is a responsible owner of an asset when a 'primary' or
//     'secondary' row names them directly ("assigned to me", fix-applied).
//
// asset_owners has no tenant_id: every query here reaches the tenant through
// assets (and tenant_members for the user).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/accesscontrol"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// responsibleOwnerTypesSQL is the SQL list of ownership types that make a user
// responsible for an asset's findings.
const responsibleOwnerTypesSQL = `('primary', 'secondary')`

// primaryUserOwnerSQL is a scalar subquery: the primary user owner of the
// asset whose id is assetExpr (NULL when it has none).
func primaryUserOwnerSQL(assetExpr string) string {
	return fmt.Sprintf(`(SELECT pao.user_id FROM asset_owners pao
		WHERE pao.asset_id = %s AND pao.user_id IS NOT NULL AND pao.ownership_type = 'primary'
		ORDER BY pao.assigned_at, pao.id LIMIT 1)`, assetExpr)
}

// assetsOwnedByUserSQL is a subquery of the ids of the tenant's assets the
// user is a responsible owner of. userParam and tenantParam are placeholders
// or column expressions.
func assetsOwnedByUserSQL(userParam, tenantParam string) string {
	return fmt.Sprintf(`(SELECT oao.asset_id FROM asset_owners oao
		JOIN assets oa ON oa.id = oao.asset_id AND oa.tenant_id = %[2]s
		WHERE oao.user_id = %[1]s AND oao.ownership_type IN %[3]s)`,
		userParam, tenantParam, responsibleOwnerTypesSQL)
}

// GetPrimaryUserOwnersByAssetIDs implements accesscontrol.Repository.
func (r *AccessControlRepository) GetPrimaryUserOwnersByAssetIDs(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]shared.ID, error) {
	result := make(map[shared.ID]shared.ID, len(assetIDs))
	if len(assetIDs) == 0 {
		return result, nil
	}
	ids := make([]string, len(assetIDs))
	for i, id := range assetIDs {
		ids[i] = id.String()
	}

	const query = `
		SELECT DISTINCT ON (ao.asset_id) ao.asset_id::text, ao.user_id::text
		FROM asset_owners ao
		JOIN assets a ON a.id = ao.asset_id AND a.tenant_id = $2
		JOIN tenant_members tm ON tm.user_id = ao.user_id AND tm.tenant_id = $2
		WHERE ao.asset_id = ANY($1::uuid[])
		  AND ao.user_id IS NOT NULL
		  AND ao.ownership_type = 'primary'
		ORDER BY ao.asset_id, ao.assigned_at, ao.id`

	rows, err := r.db.QueryContext(ctx, query, pq.Array(ids), tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get primary user owners: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var assetStr, userStr string
		if err := rows.Scan(&assetStr, &userStr); err != nil {
			return nil, fmt.Errorf("failed to scan primary user owner: %w", err)
		}
		assetID, err := shared.IDFromString(assetStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse asset ID: %w", err)
		}
		userID, err := shared.IDFromString(userStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse user ID: %w", err)
		}
		result[assetID] = userID
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate primary user owners: %w", err)
	}
	return result, nil
}

// FilterAssetsOwnedByUser implements accesscontrol.Repository.
func (r *AccessControlRepository) FilterAssetsOwnedByUser(ctx context.Context, tenantID, userID shared.ID, assetIDs []shared.ID) (map[shared.ID]bool, error) {
	result := make(map[shared.ID]bool, len(assetIDs))
	if len(assetIDs) == 0 {
		return result, nil
	}
	ids := make([]string, len(assetIDs))
	for i, id := range assetIDs {
		ids[i] = id.String()
	}

	query := `SELECT DISTINCT ao.asset_id::text
		FROM asset_owners ao
		JOIN assets a ON a.id = ao.asset_id AND a.tenant_id = $2
		WHERE ao.asset_id = ANY($1::uuid[])
		  AND ao.user_id = $3
		  AND ao.ownership_type IN ` + responsibleOwnerTypesSQL

	rows, err := r.db.QueryContext(ctx, query, pq.Array(ids), tenantID.String(), userID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to filter assets owned by user: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var assetStr string
		if err := rows.Scan(&assetStr); err != nil {
			return nil, fmt.Errorf("failed to scan owned asset: %w", err)
		}
		assetID, err := shared.IDFromString(assetStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse asset ID: %w", err)
		}
		result[assetID] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate owned assets: %w", err)
	}
	return result, nil
}

// SyncOwnerRefOwner implements accesscontrol.Repository.
func (r *AccessControlRepository) SyncOwnerRefOwner(ctx context.Context, tenantID, assetID shared.ID, userID *shared.ID) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin owner_ref sync: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var keep any
	if userID != nil {
		keep = userID.String()
	}

	// Remove the row derived from a previous owner_ref.
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM asset_owners ao
		USING assets a
		WHERE ao.asset_id = $1
		  AND a.id = ao.asset_id AND a.tenant_id = $2
		  AND ao.assignment_source = $3
		  AND ao.user_id IS DISTINCT FROM $4::uuid`,
		assetID.String(), tenantID.String(), accesscontrol.AssignmentSourceOwnerRef, keep); err != nil {
		return fmt.Errorf("failed to remove stale owner_ref owner: %w", err)
	}

	if userID != nil {
		// The unique index (asset_id, user_id) keeps an existing row (of any
		// type or source) as it is.
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO asset_owners (asset_id, user_id, ownership_type, assigned_at, assignment_source)
			SELECT a.id, $3::uuid, $4, NOW(), $5
			FROM assets a
			WHERE a.id = $1 AND a.tenant_id = $2 AND a.deleted_at IS NULL
			  AND EXISTS (SELECT 1 FROM tenant_members tm WHERE tm.user_id = $3::uuid AND tm.tenant_id = $2)
			ON CONFLICT DO NOTHING`,
			assetID.String(), tenantID.String(), userID.String(),
			string(accesscontrol.OwnershipPrimary), accesscontrol.AssignmentSourceOwnerRef); err != nil {
			return fmt.Errorf("failed to add owner_ref owner: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit owner_ref sync: %w", err)
	}
	return nil
}

// GetAssetOwnerSource implements accesscontrol.Repository.
func (r *AccessControlRepository) GetAssetOwnerSource(ctx context.Context, id shared.ID) (string, error) {
	var source sql.NullString
	err := r.db.QueryRowContext(ctx,
		`SELECT assignment_source FROM asset_owners WHERE id = $1`, id.String()).Scan(&source)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", accesscontrol.ErrAssetOwnerNotFound
		}
		return "", fmt.Errorf("failed to get asset owner source: %w", err)
	}
	if !source.Valid || source.String == "" {
		return accesscontrol.AssignmentSourceManual, nil
	}
	return source.String, nil
}
