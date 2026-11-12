package postgres

// Scope status of an inventory asset, in SQL, for list filters (research/124,
// RFC-054 §15): which assets the organization's scope covers, which no entry
// covers (passive only), which it excluded or marked not its own, and which
// are internal (governed by scan zones, not by internet scope).
//
// The match mirrors the scope coverage count (scope_coverage_repository.go)
// and pkg/domain/scope on the asset's host (the name, or the host of a URL or
// host:port). It is a filter: the active-scan gate (easm.ActiveGate) stays
// the authority on what a scan may reach, and the list shows the gate's own
// answer per row. Every subquery is pinned to the asset's tenant.

import (
	"context"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/assetlist"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Scope statuses of the asset list filter (?scope_status=).
const (
	ScopeStatusInScope    = assetlist.ScopeStatusInScope
	ScopeStatusNotCovered = assetlist.ScopeStatusNotCovered
	ScopeStatusExcluded   = assetlist.ScopeStatusExcluded
	ScopeStatusInternal   = assetlist.ScopeStatusInternal
)

// The SQL lives in pkg/domain/assetlist, shared with the list registry.
func assetHostSQL(a string) string { return assetlist.HostSQL(a) }

func scopePatternMatchSQL(kind, pattern, h, i, n string) string {
	return assetlist.ScopePatternMatchSQL(kind, pattern, h, i, n)
}

func assetScopeStatusSQL(a string) string { return assetlist.ScopeStatusSQL(a) }

func assetMonitoringStateSQL(a, scanned string) string {
	return assetlist.MonitoringStateSQL(a, scanned)
}

// MonitoringStates returns the derived monitoring state of each of the
// tenant's assets among ids (at most a list page), by id. An id that is not
// the tenant's live asset is absent.
func (r *AssetRepository) MonitoringStates(ctx context.Context, tenantID shared.ID, ids []string, unclassifiedScanned bool) (map[string]string, error) {
	out := make(map[string]string, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `SELECT a.id, `+assetMonitoringStateSQL("a", "$3::boolean")+`
		FROM assets a WHERE a.tenant_id = $1 AND a.id = ANY($2::uuid[]) AND a.deleted_at IS NULL`,
		tenantID.String(), pq.Array(ids), unclassifiedScanned)
	if err != nil {
		return nil, fmt.Errorf("asset monitoring states: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id, state string
		if err := rows.Scan(&id, &state); err != nil {
			return nil, fmt.Errorf("scan asset monitoring state: %w", err)
		}
		out[id] = state
	}
	return out, rows.Err()
}
