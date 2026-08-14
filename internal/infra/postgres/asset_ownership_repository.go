package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"
	"github.com/openctemio/api/internal/app/finding"
	"github.com/openctemio/api/pkg/domain/shared"
)

// AssetOwnershipLookupRepo reports, per asset, whether the asset has an assigned
// owner (a user or group in asset_owners). It implements finding.AssetOwnerLookup
// with ONE batch, tenant-scoped query — no per-finding N+1 — backing the CTEM
// "ownership unknown defaults to P2 minimum" floor.
//
// asset_owners has no tenant_id column, so the query tenant-scopes through the
// principal exactly as GetPrimaryOwnersByAssetIDs does: a group owner must belong
// to a group in this tenant, and a user owner must be a member of this tenant.
// Any ownership_type counts (primary or otherwise) — "has an assigned owner"
// means someone is accountable, not specifically a primary owner.
type AssetOwnershipLookupRepo struct {
	db *sql.DB
}

// NewAssetOwnershipLookupRepo creates the owner-presence lookup adapter.
func NewAssetOwnershipLookupRepo(db *sql.DB) *AssetOwnershipLookupRepo {
	return &AssetOwnershipLookupRepo{db: db}
}

var _ finding.AssetOwnerLookup = (*AssetOwnershipLookupRepo)(nil)

// HasOwnerByAssetIDs returns, keyed by asset ID, true for each asset that has at
// least one tenant-valid assigned owner. Assets with no owner are absent from the
// map (read as "no owner" by the caller). One tenant-scoped query.
func (r *AssetOwnershipLookupRepo) HasOwnerByAssetIDs(
	ctx context.Context,
	tenantID shared.ID,
	assetIDs []shared.ID,
) (map[shared.ID]bool, error) {
	result := make(map[shared.ID]bool, len(assetIDs))
	if len(assetIDs) == 0 {
		return result, nil
	}

	ids := make([]string, len(assetIDs))
	for i, id := range assetIDs {
		ids[i] = id.String()
	}

	query := `
		SELECT DISTINCT ao.asset_id::text
		FROM asset_owners ao
		WHERE ao.asset_id = ANY($1)
		  AND (ao.group_id IS NULL OR ao.group_id IN (SELECT id FROM groups WHERE tenant_id = $2))
		  AND (ao.user_id IS NULL OR ao.user_id IN (SELECT user_id FROM tenant_members WHERE tenant_id = $2))`

	rows, err := r.db.QueryContext(ctx, query, pq.Array(ids), tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("asset owner presence lookup: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var aidStr string
		if err := rows.Scan(&aidStr); err != nil {
			return nil, fmt.Errorf("scan asset owner presence: %w", err)
		}
		aid, err := shared.IDFromString(aidStr)
		if err != nil {
			continue
		}
		result[aid] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate asset owner presence: %w", err)
	}
	return result, nil
}
