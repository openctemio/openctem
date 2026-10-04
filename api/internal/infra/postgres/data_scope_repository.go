package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// DataScopeRepository answers the Layer 2 data-scope questions over
// user_accessible_assets (indexes: (user_id, asset_id), (tenant_id, user_id)).
// It implements datascope.Repository.
type DataScopeRepository struct {
	db *DB
}

// NewDataScopeRepository creates a DataScopeRepository.
func NewDataScopeRepository(db *DB) *DataScopeRepository {
	return &DataScopeRepository{db: db}
}

// HasAnyScopeAssignment reports whether the user has any scope row in the tenant.
func (r *DataScopeRepository) HasAnyScopeAssignment(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
	var exists bool
	err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM user_accessible_assets WHERE user_id = $1 AND tenant_id = $2)`,
		userID.String(), tenantID.String()).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check scope assignment: %w", err)
	}
	return exists, nil
}

// AssetIDsInScope returns the subset of assetIDs the user has a scope row for.
func (r *DataScopeRepository) AssetIDsInScope(ctx context.Context, tenantID, userID shared.ID, assetIDs []shared.ID) ([]shared.ID, error) {
	if len(assetIDs) == 0 {
		return nil, nil
	}
	ids := make([]string, len(assetIDs))
	for i, id := range assetIDs {
		ids[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT asset_id FROM user_accessible_assets
		 WHERE user_id = $1 AND tenant_id = $2 AND asset_id = ANY($3::uuid[])`,
		userID.String(), tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("list in-scope assets: %w", err)
	}
	defer rows.Close()
	out := make([]shared.ID, 0, len(assetIDs))
	for rows.Next() {
		var id shared.ID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan in-scope asset: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// FindingIDsInScope returns the subset of findingIDs (in the tenant) whose
// asset the user has a scope row for.
func (r *DataScopeRepository) FindingIDsInScope(ctx context.Context, tenantID, userID shared.ID, findingIDs []shared.ID) ([]shared.ID, error) {
	if len(findingIDs) == 0 {
		return nil, nil
	}
	ids := make([]string, len(findingIDs))
	for i, id := range findingIDs {
		ids[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT f.id FROM findings f
		 WHERE f.tenant_id = $2 AND f.id = ANY($3::uuid[])
		   AND f.asset_id IN (SELECT uaa.asset_id FROM user_accessible_assets uaa
		                      WHERE uaa.user_id = $1 AND uaa.tenant_id = $2)`,
		userID.String(), tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("list in-scope findings: %w", err)
	}
	defer rows.Close()
	out := make([]shared.ID, 0, len(findingIDs))
	for rows.Next() {
		var id shared.ID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan in-scope finding: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// FindingAssetID returns the asset of a finding in the tenant.
func (r *DataScopeRepository) FindingAssetID(ctx context.Context, tenantID, findingID shared.ID) (shared.ID, error) {
	var assetID sql.NullString
	err := r.db.QueryRowContext(ctx,
		`SELECT asset_id::text FROM findings WHERE id = $1 AND tenant_id = $2`,
		findingID.String(), tenantID.String()).Scan(&assetID)
	if errors.Is(err, sql.ErrNoRows) {
		return shared.ID{}, shared.ErrNotFound
	}
	if err != nil {
		return shared.ID{}, fmt.Errorf("lookup finding asset: %w", err)
	}
	if !assetID.Valid {
		// A finding with no inventory asset is in nobody's asset scope.
		return shared.ID{}, nil
	}
	return shared.IDFromString(assetID.String)
}

// sqlTrue is the predicate an unrestricted (nil) data scope adds.
const sqlTrue = "TRUE"

// dataScopeCond returns the SQL predicate "assetExpr is in the data scope"
// with its two arguments appended to args, numbered after the existing ones.
// A nil scope returns "TRUE" and leaves args unchanged.
//
// Every scoped read builds its predicate here, so the rule (and its use of the
// (user_id, asset_id) index) is written once.
func dataScopeCond(assetExpr string, scope *shared.DataScope, args []any) (string, []any) {
	if scope == nil {
		return sqlTrue, args
	}
	cond, scopeArgs := dataScopeCondAt(assetExpr, scope, len(args)+1)
	return cond, append(args, scopeArgs...)
}

// pairInScopeCond is dataScopeCond for a row that links two assets (a
// relationship, a suggestion): both ends must be in the scope, because the
// row names the other asset. A nil scope returns "TRUE" and leaves args
// unchanged.
func pairInScopeCond(sourceExpr, targetExpr string, scope *shared.DataScope, args []any) (string, []any) {
	if scope == nil {
		return sqlTrue, args
	}
	src, scopeArgs := dataScopeCondAt(sourceExpr, scope, len(args)+1)
	dst, _ := dataScopeCondAt(targetExpr, scope, len(args)+1)
	return "(" + src + " AND " + dst + ")", append(args, scopeArgs...)
}

// dataScopeCondAt is dataScopeCond for builders that number their own
// placeholders: the predicate uses $first and $first+1, and the two
// arguments are returned for the caller to append. scope must not be nil.
func dataScopeCondAt(assetExpr string, scope *shared.DataScope, first int) (string, []any) {
	return fmt.Sprintf(
			"%s IN (SELECT uaa.asset_id FROM user_accessible_assets uaa WHERE uaa.user_id = $%d AND uaa.tenant_id = $%d)",
			assetExpr, first, first+1),
		[]any{scope.UserID.String(), scope.TenantID.String()}
}
