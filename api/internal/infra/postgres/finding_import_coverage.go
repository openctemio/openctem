package postgres

// Full-coverage uploads (docs/rfcs/RFC-122-ingest-receipts.md §5): an
// upload that declares full coverage of an explicit scope (assets + the
// file's tool) closes the open findings of that scope it did not report.
// The candidates are the same as a covered scan's: not a human source, not
// a leaked secret (its absence does not revoke it), not a branch occurrence,
// last seen by the same tool. Every statement is scoped by tenant_id.

import (
	"context"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// importCoverageScope is the WHERE clause of a full-coverage upload's scope
// ($1 tenant, $2 assets, $3 tool, $4 the upload's receipt id).
var importCoverageScope = `
	f.tenant_id = $1
	AND f.asset_id = ANY($2::uuid[])
	AND COALESCE(f.last_seen_tool, f.tool_name) = $3
	AND f.branch_id IS NULL
	AND f.status IN ` + autoResolveFromSQL + `
	AND f.source NOT IN ` + coverageProtectedSources

// ImportCoverageCandidates returns the open findings of the scope the upload
// (receiptID, its report id and so the scan_id of what it reported) did not
// report, and how many open findings the scope has (the blinding guard).
func (r *FindingRepository) ImportCoverageCandidates(ctx context.Context, tenantID shared.ID, assets []shared.ID, tool string,
	receiptID shared.ID) (stale []shared.ID, open int, err error) {
	if len(assets) == 0 || tool == "" {
		return nil, 0, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT f.id::text, COUNT(*) OVER (),
			COALESCE(f.scan_id, '') <> $4 AND NOT `+secretFindingSQL("f")+`
		FROM findings f
		WHERE `+importCoverageScope,
		tenantID.String(), pq.Array(importScopeIDs(assets)), tool, receiptID.String())
	if err != nil {
		return nil, 0, fmt.Errorf("import coverage candidates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		var isStale bool
		if err := rows.Scan(&id, &open, &isStale); err != nil {
			return nil, 0, fmt.Errorf("scan import coverage candidate: %w", err)
		}
		if isStale {
			if fid, err := shared.IDFromString(id); err == nil {
				stale = append(stale, fid)
			}
		}
	}
	return stale, open, rows.Err()
}

// ResolveImportCoverage closes the given findings as no longer reported by a
// full-coverage upload; the UPDATE re-checks the scope, so a finding someone
// triaged meanwhile, or that the upload reported after all, stays.
func (r *FindingRepository) ResolveImportCoverage(ctx context.Context, tenantID shared.ID, assets, ids []shared.ID, tool string,
	receiptID shared.ID) ([]shared.ID, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	if autoResolvePaused(ctx, r.db, tenantID.String()) {
		return nil, nil
	}
	return r.db.queryIDsWithTransition(ctx, findingTransition{ActivityType: "auto_resolved", Source: "auto",
		Reason: "not_in_full_coverage_import", ActorType: "scanner", ActorName: "system: full-coverage import",
		Message: "An upload that declared full coverage of its assets for this tool no longer reported it"}, `
		UPDATE findings f
		SET status = 'resolved', resolution = 'auto_fixed', closure_reason = 'fixed', verification = 'covered_scan',
			resolved_at = NOW(), updated_at = NOW()
		WHERE `+importCoverageScope+`
			AND COALESCE(f.scan_id, '') <> $4
			AND NOT `+secretFindingSQL("f")+`
			AND f.id = ANY($5::uuid[])
		RETURNING f.id::text`,
		tenantID.String(), pq.Array(importScopeIDs(assets)), tool, receiptID.String(), pq.Array(importScopeIDs(ids)))
}

// ImportCoverageUntouched counts the open findings of the scope the upload
// neither reported nor closed (run after ResolveImportCoverage).
func (r *FindingRepository) ImportCoverageUntouched(ctx context.Context, tenantID shared.ID, assets []shared.ID, tool string,
	receiptID shared.ID) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM findings f WHERE `+importCoverageScope+`
		AND COALESCE(f.scan_id, '') <> $4`,
		tenantID.String(), pq.Array(importScopeIDs(assets)), tool, receiptID.String()).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("import coverage untouched: %w", err)
	}
	return n, nil
}

// CountTenantAssets returns how many of ids are live assets of the tenant.
func (r *FindingRepository) CountTenantAssets(ctx context.Context, tenantID shared.ID, ids []shared.ID) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT count(DISTINCT id) FROM assets WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND deleted_at IS NULL`,
		tenantID.String(), pq.Array(importScopeIDs(ids))).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count tenant assets: %w", err)
	}
	return n, nil
}

func importScopeIDs(ids []shared.ID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}
