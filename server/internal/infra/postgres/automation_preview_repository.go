package postgres

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// LatestFindingIDs returns the ids of the tenant's latest findings inside
// scope (nil: every finding) that the reader may see under the pentest
// member-visibility rule, newest first. Automation preview samples them.
func (r *AutomationRunRepository) LatestFindingIDs(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, limit int) ([]shared.ID, error) {
	args := []any{tenantID.String(), limit}
	cond := "TRUE"
	if scope != nil {
		var sa []any
		cond, sa = filterspec.AssigneeScopeSQL("f.asset_id", "f.assigned_to", scope, 3)
		args = append(args, sa...)
		cond += " AND " + runFindingVisibleSQL(ctx, "f", "$1", scope)
	}
	return r.latestIDs(ctx, `SELECT f.id FROM findings f WHERE f.tenant_id = $1 AND `+cond+` ORDER BY f.created_at DESC LIMIT $2`, args)
}

// LatestAssetIDs is LatestFindingIDs for assets.
func (r *AutomationRunRepository) LatestAssetIDs(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, limit int) ([]shared.ID, error) {
	args := []any{tenantID.String(), limit}
	cond := "TRUE"
	if scope != nil {
		var sa []any
		cond, sa = filterspec.ScopeSQL("a.id", scope, 3)
		args = append(args, sa...)
	}
	return r.latestIDs(ctx, `SELECT a.id FROM assets a WHERE a.tenant_id = $1 AND `+cond+` ORDER BY a.created_at DESC LIMIT $2`, args)
}

func (r *AutomationRunRepository) latestIDs(ctx context.Context, q string, args []any) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("sample preview subjects: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if pid, err := shared.IDFromString(id); err == nil {
			out = append(out, pid)
		}
	}
	return out, rows.Err()
}
