package postgres

// Explicit per-user data-scope grants (asset_access_grants, migration 000372).
//
// Being an asset owner is an assignment only; it does not change what the
// owner can see. A user's data scope (user_accessible_assets) is the assets
// of their active groups plus these grants. Each write updates
// user_accessible_assets in the same transaction, through the SQL functions
// refresh_access_for_grant_add / refresh_access_for_grant_remove.
//
// Tenant isolation: the asset and the user are both checked against the
// caller's tenant in SQL (assets.tenant_id, tenant_members), never taken from
// the request alone.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/accesscontrol"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const assetAccessGrantColumns = `
	g.id::text, g.tenant_id::text, g.asset_id::text, g.user_id::text,
	COALESCE(u.name, ''), COALESCE(u.email, ''), g.source,
	g.granted_by::text, COALESCE(gb.name, ''), g.granted_at`

const assetAccessGrantFrom = `
	FROM asset_access_grants g
	LEFT JOIN users u ON u.id = g.user_id
	LEFT JOIN users gb ON gb.id = g.granted_by`

func scanAssetAccessGrant(scan func(dest ...any) error) (*accesscontrol.AssetAccessGrant, error) {
	var (
		id, tenantID, assetID, userID string
		grantedBy                     sql.NullString
		grantedAt                     time.Time
		g                             accesscontrol.AssetAccessGrant
	)
	if err := scan(&id, &tenantID, &assetID, &userID, &g.UserName, &g.UserEmail, &g.Source,
		&grantedBy, &g.GrantedByName, &grantedAt); err != nil {
		return nil, err
	}
	var err error
	if g.ID, err = shared.IDFromString(id); err != nil {
		return nil, fmt.Errorf("parse grant id: %w", err)
	}
	if g.TenantID, err = shared.IDFromString(tenantID); err != nil {
		return nil, fmt.Errorf("parse tenant id: %w", err)
	}
	if g.AssetID, err = shared.IDFromString(assetID); err != nil {
		return nil, fmt.Errorf("parse asset id: %w", err)
	}
	if g.UserID, err = shared.IDFromString(userID); err != nil {
		return nil, fmt.Errorf("parse user id: %w", err)
	}
	if grantedBy.Valid {
		by, err := shared.IDFromString(grantedBy.String)
		if err != nil {
			return nil, fmt.Errorf("parse granted_by: %w", err)
		}
		g.GrantedBy = &by
	}
	g.GrantedAt = grantedAt
	return &g, nil
}

// ListAssetAccessGrants implements accesscontrol.Repository.
func (r *AccessControlRepository) ListAssetAccessGrants(ctx context.Context, tenantID, assetID shared.ID) ([]*accesscontrol.AssetAccessGrant, error) {
	query := `SELECT ` + assetAccessGrantColumns + assetAccessGrantFrom + `
		WHERE g.tenant_id = $1 AND g.asset_id = $2
		ORDER BY g.granted_at, g.id`
	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), assetID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list access grants: %w", err)
	}
	defer rows.Close()

	out := make([]*accesscontrol.AssetAccessGrant, 0)
	for rows.Next() {
		g, err := scanAssetAccessGrant(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("failed to scan access grant: %w", err)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate access grants: %w", err)
	}
	return out, nil
}

// CreateAssetAccessGrant implements accesscontrol.Repository.
func (r *AccessControlRepository) CreateAssetAccessGrant(ctx context.Context, tenantID, assetID, userID shared.ID, grantedBy *shared.ID) (*accesscontrol.AssetAccessGrant, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin access grant: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var by any
	if grantedBy != nil {
		by = grantedBy.String()
	}
	// The asset must belong to the tenant and the user must be a member of
	// it; otherwise nothing is inserted and the caller gets not-found.
	var id string
	err = tx.QueryRowContext(ctx, `
		INSERT INTO asset_access_grants (tenant_id, asset_id, user_id, source, granted_by)
		SELECT a.tenant_id, a.id, tm.user_id, 'manual', $4::uuid
		FROM assets a
		JOIN tenant_members tm ON tm.tenant_id = a.tenant_id AND tm.user_id = $3::uuid
		WHERE a.id = $2 AND a.tenant_id = $1
		RETURNING id::text`,
		tenantID.String(), assetID.String(), userID.String(), by).Scan(&id)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, accesscontrol.ErrAccessGrantExists
		}
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: asset or user not in this tenant", shared.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to create access grant: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `SELECT refresh_access_for_grant_add($1, $2)`, assetID.String(), userID.String()); err != nil {
		return nil, fmt.Errorf("failed to refresh access for grant: %w", err)
	}

	g, err := scanAssetAccessGrant(tx.QueryRowContext(ctx,
		`SELECT `+assetAccessGrantColumns+assetAccessGrantFrom+` WHERE g.id = $1`, id).Scan)
	if err != nil {
		return nil, fmt.Errorf("failed to read access grant: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit access grant: %w", err)
	}
	return g, nil
}

// DeleteAssetAccessGrant implements accesscontrol.Repository.
func (r *AccessControlRepository) DeleteAssetAccessGrant(ctx context.Context, tenantID, assetID, grantID shared.ID) (*accesscontrol.AssetAccessGrant, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin access grant revoke: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	g, err := scanAssetAccessGrant(tx.QueryRowContext(ctx,
		`SELECT `+assetAccessGrantColumns+assetAccessGrantFrom+`
		 WHERE g.id = $1 AND g.tenant_id = $2 AND g.asset_id = $3
		 FOR UPDATE OF g`,
		grantID.String(), tenantID.String(), assetID.String()).Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, accesscontrol.ErrAccessGrantNotFound
		}
		return nil, fmt.Errorf("failed to load access grant: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM asset_access_grants WHERE id = $1`, grantID.String()); err != nil {
		return nil, fmt.Errorf("failed to delete access grant: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT refresh_access_for_grant_remove($1, $2)`, g.AssetID.String(), g.UserID.String()); err != nil {
		return nil, fmt.Errorf("failed to refresh access after revoke: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit access grant revoke: %w", err)
	}
	return g, nil
}
