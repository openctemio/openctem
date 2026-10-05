package postgres

import (
	"context"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Default-branch (repository) auto-resolve, decided per scan command: the
// queries behind ingest.Service.evaluateRepoCoverage (research 18 F3).
//
// A repository finding closes only when a later run of the SAME tool and the
// SAME scan profile, bound to a command that completed cleanly, covered its
// asset and did not report it. The profile stands in for the ruleset until
// runs carry a ruleset digest: a finding last seen under another profile (a
// different config, a wider ruleset) or by a report not tied to a command (a
// v1 or CI upload) is never a candidate.

// RepoCoverageStaleFindings returns the open default-branch findings of the
// query's tool on its assets that the run did not report and whose last
// sighting was a report of the same tool under the same scan profile, plus
// how many open default-branch findings of that tool those assets have (for
// the blinding guard).
func (r *FindingRepository) RepoCoverageStaleFindings(ctx context.Context, tenantID shared.ID, q ingestreport.CoverageQuery) ([]shared.ID, int, error) {
	if len(q.AssetIDs) == 0 || q.ToolName == "" || len(q.SeenScanIDs) == 0 {
		return nil, 0, nil
	}
	assets := make([]string, len(q.AssetIDs))
	for i, a := range q.AssetIDs {
		assets[i] = a.String()
	}
	rows, err := r.db.QueryContext(ctx, `
		WITH open_findings AS (
			SELECT f.id, f.tenant_id, f.scan_id
			FROM findings f
			JOIN repository_branches rb ON rb.id = f.branch_id AND rb.is_default = true
			WHERE f.tenant_id = $1
				AND f.asset_id = ANY($2)
				-- Only the tool that saw the finding last may close it
				-- (RFC-043 interim guard).
				AND COALESCE(f.last_seen_tool, f.tool_name) = $3
				AND f.status IN `+coverageOpenStatuses+`
				AND f.source NOT IN `+coverageProtectedSources+`
		)
		SELECT o.id::text, COUNT(*) OVER () AS open_total,
			(
				NOT (COALESCE(o.scan_id, '') = ANY($4))
				AND EXISTS (
					SELECT 1
					FROM ingest_reports ir
					JOIN commands pc ON pc.id = ir.command_id AND pc.tenant_id = ir.tenant_id
					LEFT JOIN scans ps ON ps.tenant_id = ir.tenant_id AND ps.id::text = pc.payload->>'scan_id'
					WHERE ir.tenant_id = o.tenant_id
						AND ir.report_id::text = o.scan_id
						AND ir.tool_name = $3
						AND COALESCE(ps.profile_id::text, '') = $5
				)
			) AS stale
		FROM open_findings o`,
		tenantID.String(), pq.Array(assets), q.ToolName, pq.Array(q.SeenScanIDs), q.ProfileID)
	if err != nil {
		return nil, 0, fmt.Errorf("repository coverage stale findings: %w", err)
	}
	defer rows.Close()
	var (
		stale []shared.ID
		open  int
	)
	for rows.Next() {
		var (
			idStr   string
			isStale bool
		)
		if err := rows.Scan(&idStr, &open, &isStale); err != nil {
			return nil, 0, fmt.Errorf("scan repository coverage candidate: %w", err)
		}
		if !isStale {
			continue
		}
		if id, err := shared.IDFromString(idStr); err == nil {
			stale = append(stale, id)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate repository coverage candidates: %w", err)
	}
	return stale, open, nil
}

// ResolveRepoCoverageStale closes the given default-branch findings as
// verified by a scan, re-checking branch, status and source in the UPDATE so
// a finding someone triaged since the candidates were read is left alone.
func (r *FindingRepository) ResolveRepoCoverageStale(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]shared.ID, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	// A re-fingerprint run is re-keying this tenant (RFC-043 D11).
	if autoResolvePaused(ctx, r.db, tenantID.String()) {
		return nil, nil
	}
	idStrs := make([]string, len(ids))
	for i, id := range ids {
		idStrs[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx, `
		UPDATE findings f
		SET status = 'resolved',
			resolution = 'auto_fixed',
			resolution_method = 'scan_verified',
			resolved_at = NOW(),
			updated_at = NOW()
		FROM repository_branches rb
		WHERE f.tenant_id = $1
			AND f.id = ANY($2)
			AND f.branch_id = rb.id
			AND rb.is_default = true
			AND f.status IN `+coverageOpenStatuses+`
			AND f.source NOT IN `+coverageProtectedSources+`
		RETURNING f.id::text`, tenantID.String(), pq.Array(idStrs))
	if err != nil {
		return nil, fmt.Errorf("resolve repository coverage-stale findings: %w", err)
	}
	defer rows.Close()
	var resolved []shared.ID
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return nil, fmt.Errorf("scan resolved finding id: %w", err)
		}
		if id, err := shared.IDFromString(idStr); err == nil {
			resolved = append(resolved, id)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate resolved findings: %w", err)
	}
	return resolved, nil
}
