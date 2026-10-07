package postgres

// Reads for the scope join (RFC-054 §4.3): the automatic records still in
// review, which a permanent scope target or seed may now confirm.

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ easm.ScopeJoinStore = (*AttributionRepository)(nil)

// PendingAutomatic lists up to limit of the tenant's live assets whose record
// is needs_review or candidate and was not decided by a person, oldest record
// first. Tenant-scoped on both tables.
func (r *AttributionRepository) PendingAutomatic(ctx context.Context, tenantID shared.ID, limit int) ([]easm.JoinItem, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT a.id, a.name, a.asset_type, COALESCE(a.sub_type, '')
		FROM asset_attributions aa
		JOIN assets a ON a.id = aa.asset_id AND a.tenant_id = aa.tenant_id
		WHERE aa.tenant_id = $1
		  AND aa.state IN ('needs_review', 'candidate')
		  AND aa.decided_at IS NULL
		  AND a.deleted_at IS NULL
		ORDER BY aa.created_at, a.id
		LIMIT $2`, tenantID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("list pending attribution: %w", err)
	}
	defer rows.Close()
	var out []easm.JoinItem
	for rows.Next() {
		var it easm.JoinItem
		var typ string
		if err := rows.Scan(&it.ID, &it.Name, &typ, &it.SubType); err != nil {
			return nil, err
		}
		it.Type = asset.AssetType(typ)
		out = append(out, it)
	}
	return out, rows.Err()
}

// TenantsWithPendingAutomatic lists the tenants that have automatic records
// in review. A system read for the backfill; each tenant is then processed
// with tenant-scoped queries only.
func (r *AttributionRepository) TenantsWithPendingAutomatic(ctx context.Context) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT tenant_id FROM asset_attributions
		WHERE state IN ('needs_review', 'candidate') AND decided_at IS NULL`)
	if err != nil {
		return nil, fmt.Errorf("list tenants with pending attribution: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		id, err := shared.IDFromString(raw)
		if err != nil {
			continue
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
