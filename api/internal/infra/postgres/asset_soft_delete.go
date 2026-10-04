package postgres

// Safe asset delete (owner decision O3, migrations 000378-000380).
//
// A person's delete never destroys findings. An asset that has findings is
// refused (archive it instead); one without findings is soft-deleted:
//
//   - assets.deleted_at / deleted_by are set and every read excludes the row
//     (liveAssetSQL);
//   - the name is freed: the full (tenant_id, name) unique key stays in place
//     for pods of the previous release, so the row keeps a unique tombstone
//     name and the original goes to the audit log, letting the same name be
//     created again at once;
//   - the asset is detached from everything that would surface it or route
//     work to it: groups, owners, data scope, grants, relationships,
//     suggestions, business units and services, controls, identifiers, scan
//     coverage, its discovered services and components, pending dedup reviews,
//     and its children's parent link;
//   - its history (state history, exposures, attribution evidence) stays for
//     the retention period; PurgeDeleted then hard-deletes the row.
//
// findings.asset_id is ON DELETE NO ACTION, so even the purge (or any other
// hard delete) cannot take findings with it.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// liveAssetSQL is the predicate every read of assets carries: soft-deleted
// rows are invisible. alias is the assets alias ("a"), or "" for an
// unaliased FROM assets.
func liveAssetSQL(alias string) string {
	if alias == "" {
		return "deleted_at IS NULL"
	}
	return alias + ".deleted_at IS NULL"
}

// notOfDeletedAssetSQL is the predicate for rows that point at an asset
// (exposure events, ...): a row of a soft-deleted asset is history, not
// work, so it is not listed or counted. col is the asset id column; a NULL
// asset id stays visible.
func notOfDeletedAssetSQL(col string) string {
	return "NOT EXISTS (SELECT 1 FROM assets d WHERE d.id = " + col + " AND d.deleted_at IS NOT NULL)"
}

// assetDetachStatements remove the rows that make a deleted asset appear in
// lists or receive work. $1 is the asset id (already checked against the
// tenant).
var assetDetachStatements = []string{
	`DELETE FROM asset_group_members WHERE asset_id = $1`,
	`DELETE FROM user_accessible_assets WHERE asset_id = $1`,
	`DELETE FROM asset_access_grants WHERE asset_id = $1`,
	`DELETE FROM asset_owners WHERE asset_id = $1`,
	`DELETE FROM asset_relationships WHERE source_asset_id = $1 OR target_asset_id = $1`,
	`DELETE FROM relationship_suggestions WHERE source_asset_id = $1 OR target_asset_id = $1`,
	`DELETE FROM business_unit_assets WHERE asset_id = $1`,
	`DELETE FROM business_service_assets WHERE asset_id = $1`,
	`DELETE FROM compensating_control_assets WHERE asset_id = $1`,
	`DELETE FROM asset_identifiers WHERE asset_id = $1`,
	`DELETE FROM scan_coverage_state WHERE asset_id = $1`,
	`DELETE FROM asset_services WHERE asset_id = $1`,
	`DELETE FROM asset_components WHERE asset_id = $1`,
	`DELETE FROM asset_dedup_review WHERE status = 'pending' AND (keep_asset_id = $1 OR $1 = ANY(merge_asset_ids))`,
	`UPDATE assets SET parent_id = NULL WHERE parent_id = $1`,
}

// Delete implements asset.Repository: a refused-or-soft delete.
func (r *AssetRepository) Delete(ctx context.Context, tenantID, assetID shared.ID, deletedBy *shared.ID) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin asset delete: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Lock the live row of this tenant; anything else is not found.
	var found string
	err = tx.QueryRowContext(ctx,
		`SELECT id::text FROM assets WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL FOR UPDATE`,
		tenantID.String(), assetID.String()).Scan(&found)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return asset.NotFoundError(assetID)
		}
		return fmt.Errorf("failed to lock asset: %w", err)
	}

	// Any finding, whatever its status, is history that must not go.
	var findings int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM findings WHERE asset_id = $1`,
		assetID.String()).Scan(&findings); err != nil {
		return fmt.Errorf("failed to count asset findings: %w", err)
	}
	if findings > 0 {
		return &asset.HasFindingsError{AssetID: assetID, FindingCount: findings}
	}

	var by any
	if deletedBy != nil {
		by = deletedBy.String()
	}
	// Tombstone name: unique (it carries the id), within VARCHAR(255).
	if _, err := tx.ExecContext(ctx, `
		UPDATE assets
		   SET deleted_at = NOW(),
		       deleted_by = $3::uuid,
		       name = LEFT(name, 180) || ' [deleted ' || id::text || ']',
		       updated_at = NOW()
		 WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), assetID.String(), by); err != nil {
		return fmt.Errorf("failed to soft-delete asset: %w", err)
	}

	for _, stmt := range assetDetachStatements {
		if _, err := tx.ExecContext(ctx, stmt, assetID.String()); err != nil {
			return fmt.Errorf("failed to detach deleted asset: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit asset delete: %w", err)
	}
	return nil
}

// PurgeDeleted implements asset.Repository.
func (r *AssetRepository) PurgeDeleted(ctx context.Context, before time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, nil
	}
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM assets
		 WHERE id IN (
			SELECT a.id FROM assets a
			 WHERE a.deleted_at IS NOT NULL AND a.deleted_at < $1
			   AND NOT EXISTS (SELECT 1 FROM findings f WHERE f.asset_id = a.id)
			 ORDER BY a.deleted_at
			 LIMIT $2
			 FOR UPDATE SKIP LOCKED)`,
		before, limit)
	if err != nil {
		return 0, fmt.Errorf("failed to purge deleted assets: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
