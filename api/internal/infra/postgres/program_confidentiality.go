package postgres

// Private program assets (RFC-065 §15.3, docs/rfcs/RFC-065-bug-bounty-programs.md):
// an asset is hidden from a user when it is program-only (no own scope covers
// it, assets.program_only), is linked to at least one private program, and
// none of its programs is public or has the user in its active group. Owners
// never get a scope that applies this (the enforcer decides who); the rule
// is written once, in filterspec.HiddenAssetWhere, and every scoped read
// goes through it (dataScopeCondAt, the asset list scope, the id checks).

import (
	"context"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

func hiddenAssetWhere(userArg, tenantArg int) string {
	return filterspec.HiddenAssetWhere(userArg, tenantArg)
}

func notHiddenCond(assetExpr string, userArg, tenantArg int) string {
	return filterspec.NotHiddenSQL(assetExpr, userArg, tenantArg)
}

// HasHiddenAssets reports whether any asset of the tenant is hidden from
// the user.
func (r *DataScopeRepository) HasHiddenAssets(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
	var hidden bool
	err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM assets ph WHERE `+hiddenAssetWhere(1, 2)+`)`,
		userID.String(), tenantID.String()).Scan(&hidden)
	if err != nil {
		return false, fmt.Errorf("check private program assets: %w", err)
	}
	return hidden, nil
}

// AssetIDsVisible returns the subset of assetIDs (in the tenant) that are not
// hidden from the user.
func (r *DataScopeRepository) AssetIDsVisible(ctx context.Context, tenantID, userID shared.ID, assetIDs []shared.ID) ([]shared.ID, error) {
	return r.idQuery(ctx, `SELECT a.id FROM assets a
		WHERE a.tenant_id = $2 AND a.id = ANY($3::uuid[]) AND `+notHiddenCond("a.id", 1, 2),
		tenantID, userID, assetIDs)
}

// FindingIDsVisible returns the subset of findingIDs (in the tenant) whose
// asset is not hidden from the user.
func (r *DataScopeRepository) FindingIDsVisible(ctx context.Context, tenantID, userID shared.ID, findingIDs []shared.ID) ([]shared.ID, error) {
	return r.idQuery(ctx, `SELECT f.id FROM findings f
		WHERE f.tenant_id = $2 AND f.id = ANY($3::uuid[]) AND `+notHiddenCond("f.asset_id", 1, 2),
		tenantID, userID, findingIDs)
}

// idQuery runs a query taking ($1 user, $2 tenant, $3 ids) and returning ids.
func (r *DataScopeRepository) idQuery(ctx context.Context, q string, tenantID, userID shared.ID, in []shared.ID) ([]shared.ID, error) {
	if len(in) == 0 {
		return nil, nil
	}
	ids := make([]string, len(in))
	for i, id := range in {
		ids[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx, q, userID.String(), tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("list visible rows: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]shared.ID, 0, len(in))
	for rows.Next() {
		var id shared.ID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan visible row: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
