package postgres

// Stored asset names moved to their CTIS 2.0 canonical form
// (internal/app/assetcanon). Every statement is scoped by tenant; a merge
// goes through the asset merge (mergeAssetReferences) in one transaction per
// asset, and every change is journaled in asset_canonical_changes.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/assetcanon"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CanonicalAsset is one stored asset the runner looks at.
type CanonicalAsset = assetcanon.Asset

// AssetCanonicalRepository reads and changes asset names for the runner.
type AssetCanonicalRepository struct {
	db *DB
}

// NewAssetCanonicalRepository creates the repository.
func NewAssetCanonicalRepository(db *DB) *AssetCanonicalRepository {
	return &AssetCanonicalRepository{db: db}
}

// Tenants lists the tenants with assets of a canonical type.
func (r *AssetCanonicalRepository) Tenants(ctx context.Context) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT tenant_id FROM assets
		WHERE asset_type = ANY($1::text[]) ORDER BY tenant_id`, pq.Array(assetcanon.Types))
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		id, err := shared.IDFromString(s)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// Page returns up to limit assets of the tenant of a canonical type with an
// id after afterID ("" from the start), in id order.
func (r *AssetCanonicalRepository) Page(ctx context.Context, tenantID shared.ID, afterID string, limit int) ([]CanonicalAsset, error) {
	if afterID == "" {
		afterID = noReview // the nil UUID: before every id
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id, asset_type, COALESCE(sub_type, ''), name FROM assets
		WHERE tenant_id = $1 AND asset_type = ANY($2::text[]) AND id > $3::uuid
		ORDER BY id LIMIT $4`, tenantID.String(), pq.Array(assetcanon.Types), afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("page assets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []CanonicalAsset
	for rows.Next() {
		var a CanonicalAsset
		if err := rows.Scan(&a.ID, &a.Type, &a.SubType, &a.Name); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Holder is the asset of the tenant named name, or nil.
func (r *AssetCanonicalRepository) Holder(ctx context.Context, tenantID shared.ID, name string) (*CanonicalAsset, error) {
	var a CanonicalAsset
	err := r.db.QueryRowContext(ctx, `SELECT id, asset_type, COALESCE(sub_type, ''), name FROM assets
		WHERE tenant_id = $1 AND name = $2`, tenantID.String(), name).Scan(&a.ID, &a.Type, &a.SubType, &a.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("asset by name: %w", err)
	}
	return &a, nil
}

// Rename gives the asset its canonical name when it still has the old one
// and no asset of the tenant holds the new one; false when either changed
// meanwhile (the caller looks again).
func (r *AssetCanonicalRepository) Rename(ctx context.Context, tenantID shared.ID, a CanonicalAsset, newName string) (bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	tid := tenantID.String()
	res, err := tx.ExecContext(ctx, `UPDATE assets SET name = $4, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2 AND name = $3
		  AND NOT EXISTS (SELECT 1 FROM assets o WHERE o.tenant_id = $1 AND o.name = $4)`, tid, a.ID, a.Name, newName)
	if err != nil {
		return false, fmt.Errorf("rename asset: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil
	}
	if err := journalCanonical(ctx, tx, tid, a, newName, "rename", ""); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO asset_merge_log (tenant_id, kept_asset_id, kept_asset_name,
			correlation_type, action, old_name, new_name, source, created_at)
		VALUES ($1, $2, $4, 'ctis2_canonical', 'rename', $3, $4, 'system', NOW())`, tid, a.ID, a.Name, newName); err != nil {
		return false, fmt.Errorf("log rename: %w", err)
	}
	return true, tx.Commit()
}

// Merge folds the asset into keep, which holds its canonical name, through
// the asset merge: every reference moves to keep, findings are re-keyed and
// folded, and the asset is deleted. Both must still be what the caller saw
// (same names, same type and sub-type, same tenant); false when not.
func (r *AssetCanonicalRepository) Merge(ctx context.Context, tenantID shared.ID, a, keep CanonicalAsset) (bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := setLocalStatementTimeout(ctx, tx, timeoutHeavy); err != nil {
		return false, err
	}
	tid := tenantID.String()
	var locked int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM (SELECT id FROM assets
		WHERE tenant_id = $1 AND ((id = $2 AND name = $3) OR (id = $4 AND name = $5))
		  AND asset_type = $6 AND COALESCE(sub_type, '') = $7
		ORDER BY id FOR UPDATE) l`, tid, a.ID, a.Name, keep.ID, keep.Name, a.Type, a.SubType).Scan(&locked); err != nil {
		return false, fmt.Errorf("lock assets: %w", err)
	}
	if locked != 2 || a.Type != keep.Type || a.SubType != keep.SubType {
		return false, nil
	}
	if err := mergeAssetReferences(ctx, tx, tid, noReview, keep.ID, []string{a.ID}); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO asset_merge_log (tenant_id, kept_asset_id, kept_asset_name,
			merged_asset_id, merged_asset_name, correlation_type, action, source, created_at)
		VALUES ($1, $2, $3, $4, $5, 'ctis2_canonical', 'merge', 'system', NOW())`,
		tid, keep.ID, keep.Name, a.ID, a.Name); err != nil {
		return false, fmt.Errorf("log merge: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM assets WHERE tenant_id = $1 AND id = $2`, tid, a.ID); err != nil {
		return false, fmt.Errorf("delete merged asset: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE assets SET updated_at = NOW() WHERE tenant_id = $1 AND id = $2`, tid, keep.ID); err != nil {
		return false, fmt.Errorf("touch kept asset: %w", err)
	}
	if err := journalCanonical(ctx, tx, tid, a, keep.Name, "merge", keep.ID); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// Conflict records an asset whose canonical name another type holds: it is
// left as it is (one row per asset and name).
func (r *AssetCanonicalRepository) Conflict(ctx context.Context, tenantID shared.ID, a CanonicalAsset, newName, holderID string) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO asset_canonical_changes
			(tenant_id, asset_id, asset_type, old_name, new_name, action, kept_asset_id)
		VALUES ($1, $2, $3, $4, $5, 'conflict', $6)
		ON CONFLICT (tenant_id, asset_id, new_name) WHERE action = 'conflict' DO NOTHING`,
		tenantID.String(), a.ID, a.Type, a.Name, newName, nullUUIDString(holderID))
	if err != nil {
		return fmt.Errorf("record conflict: %w", err)
	}
	return nil
}

// Revert gives every asset of the tenant the runner renamed its old name
// back, when the asset still has the canonical name and no other asset holds
// the old one. It returns how many it reverted and how many it had to keep.
// Merges are not undone.
func (r *AssetCanonicalRepository) Revert(ctx context.Context, tenantID shared.ID) (reverted, kept int, err error) {
	tid := tenantID.String()
	changes, err := r.openRenames(ctx, tid)
	if err != nil {
		return 0, 0, err
	}
	for _, c := range changes {
		ok, err := r.revertOne(ctx, tid, c.id, c.asset, c.oldName, c.newName)
		if err != nil {
			return reverted, kept, err
		}
		if ok {
			reverted++
		} else {
			kept++
		}
	}
	return reverted, kept, nil
}

type canonicalRename struct{ id, asset, oldName, newName string }

// openRenames lists the tenant's renames not reverted yet, newest first.
func (r *AssetCanonicalRepository) openRenames(ctx context.Context, tid string) ([]canonicalRename, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, asset_id, old_name, new_name FROM asset_canonical_changes
		WHERE tenant_id = $1 AND action = 'rename' AND reverted_at IS NULL ORDER BY created_at DESC`, tid)
	if err != nil {
		return nil, fmt.Errorf("list renames: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []canonicalRename
	for rows.Next() {
		var c canonicalRename
		if err := rows.Scan(&c.id, &c.asset, &c.oldName, &c.newName); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *AssetCanonicalRepository) revertOne(ctx context.Context, tid, changeID, assetID, oldName, newName string) (bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE assets SET name = $4, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2 AND name = $3
		  AND NOT EXISTS (SELECT 1 FROM assets o WHERE o.tenant_id = $1 AND o.name = $4)`, tid, assetID, newName, oldName)
	if err != nil {
		return false, fmt.Errorf("revert rename: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE asset_canonical_changes SET reverted_at = NOW()
		WHERE tenant_id = $1 AND id = $2`, tid, changeID); err != nil {
		return false, fmt.Errorf("mark reverted: %w", err)
	}
	return true, tx.Commit()
}

func journalCanonical(ctx context.Context, tx *sql.Tx, tid string, a CanonicalAsset, newName, action, keptID string) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO asset_canonical_changes
			(tenant_id, asset_id, asset_type, old_name, new_name, action, kept_asset_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, tid, a.ID, a.Type, a.Name, newName, action, nullUUIDString(keptID)); err != nil {
		return fmt.Errorf("journal %s: %w", action, err)
	}
	return nil
}

func nullUUIDString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
