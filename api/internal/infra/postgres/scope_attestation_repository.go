package postgres

// Re-attestation of intrusive (t2) scope entries (RFC-054 §12.5). The job
// reads across tenants only to find which tenants have an active t2 entry;
// every other read and write is scoped to one tenant and conditional.

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// maxIntrusivePerTenant bounds one tenant's batch in one run.
const maxIntrusivePerTenant = 1000

// TenantsWithIntrusiveEntries lists the tenants with an active t2 entry.
func (r *ScopeTargetRepository) TenantsWithIntrusiveEntries(ctx context.Context) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT tenant_id FROM scope_targets WHERE max_tier = 2 AND status = 'active'`)
	if err != nil {
		return nil, fmt.Errorf("list tenants with t2 entries: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var id shared.ID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ListActiveIntrusive lists one tenant's active t2 entries.
func (r *ScopeTargetRepository) ListActiveIntrusive(ctx context.Context, tenantID shared.ID) ([]*scope.Target, error) {
	rows, err := r.db.QueryContext(ctx, scopeTargetSelectQuery+`
		WHERE tenant_id = $1 AND max_tier = 2 AND status = 'active'
		ORDER BY created_at, id LIMIT $2`, tenantID.String(), maxIntrusivePerTenant)
	if err != nil {
		return nil, fmt.Errorf("list t2 scope targets: %w", err)
	}
	defer rows.Close()
	var out []*scope.Target
	for rows.Next() {
		t, err := r.scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// MarkAttestationRequested opens an attestation request on an active t2
// entry that has none open.
func (r *ScopeTargetRepository) MarkAttestationRequested(ctx context.Context, tenantID, id shared.ID, now time.Time) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE scope_targets SET attestation_requested_at = $3
		WHERE tenant_id = $1 AND id = $2 AND max_tier = 2 AND status = 'active'
		  AND attestation_requested_at IS NULL`,
		tenantID.String(), id.String(), now)
	if err != nil {
		return false, fmt.Errorf("request scope attestation: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// DowngradeUnattested sets a t2 entry to t1 when the request opened at
// requestedAt is still open: an attestation meanwhile (which clears the
// request) or an earlier downgrade leaves it alone. Idempotent.
func (r *ScopeTargetRepository) DowngradeUnattested(ctx context.Context, tenantID, id shared.ID, requestedAt, now time.Time) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE scope_targets
		SET max_tier = 1, attestation_requested_at = NULL, updated_at = $4
		WHERE tenant_id = $1 AND id = $2 AND max_tier = 2
		  AND attestation_requested_at = $3`,
		tenantID.String(), id.String(), requestedAt, now)
	if err != nil {
		return false, fmt.Errorf("downgrade scope target: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
