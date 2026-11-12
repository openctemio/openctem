package postgres

// Runs of a workflow scan split over several scan zones: the parent settles
// from its children. Architecture: docs/architecture/scan-zones.md ("Workflow
// runs over several zones").

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/server/pkg/domain/scanrun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

var _ scanrun.ZoneSplitStore = (*ScanRunRepository)(nil)

// ListChildRuns returns the children of parentID in tenantID, oldest first.
func (r *ScanRunRepository) ListChildRuns(ctx context.Context, tenantID, parentID shared.ID) ([]*scanrun.Run, error) {
	rows, err := r.db.QueryContext(ctx, r.selectQuery()+` WHERE tenant_id = $1 AND parent_run_id = $2 ORDER BY created_at ASC, id ASC`,
		tenantID.String(), parentID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list child runs: %w", err)
	}
	defer rows.Close()
	var out []*scanrun.Run
	for rows.Next() {
		run, err := r.scanRunFromRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

// splitOutcomeSQL settles the open parents the filter selects whose children
// all finished (scanrun.SplitOutcome in SQL). A child is joined only within
// its parent's tenant.
const splitOutcomeSQL = `
	WITH kids AS (
		SELECT p.id, p.tenant_id, p.scan_id,
		       COUNT(c.id) AS n,
		       COUNT(c.id) FILTER (WHERE c.status IN ('pending', 'running')) AS open,
		       COUNT(c.id) FILTER (WHERE c.status = 'completed') AS completed,
		       COUNT(c.id) FILTER (WHERE c.status IN ('completed', 'partial')) AS results,
		       COUNT(c.id) FILTER (WHERE c.status = 'canceled') AS canceled,
		       COALESCE(SUM(c.total_findings), 0) AS findings
		FROM scan_runs p
		JOIN scan_runs c ON c.tenant_id = p.tenant_id AND c.parent_run_id = p.id
		WHERE p.status IN ('pending', 'running') AND %s
		GROUP BY p.id, p.tenant_id, p.scan_id
	), settled AS (
		UPDATE scan_runs p
		SET status = CASE
		        WHEN k.completed = k.n THEN 'completed'
		        WHEN k.canceled = k.n THEN 'canceled'
		        WHEN k.results = 0 THEN 'failed'
		        ELSE 'partial' END,
		    completed_at = NOW(),
		    total_findings = k.findings,
		    error_message = CASE
		        WHEN k.completed = k.n OR k.canceled = k.n THEN p.error_message
		        ELSE (k.n - k.results - k.canceled)::text || ' of ' || k.n::text || ' scan zone run(s) produced no results' END
		FROM kids k
		WHERE p.id = k.id AND p.tenant_id = k.tenant_id AND k.n > 0 AND k.open = 0
		  AND p.status IN ('pending', 'running')
		RETURNING p.id, p.status, p.scan_id
	)
	SELECT id::text, status, COALESCE(scan_id::text, '') FROM settled`

// SettleSplitParent settles parentID of tenantID once its children all
// finished.
func (r *ScanRunRepository) SettleSplitParent(ctx context.Context, tenantID, parentID shared.ID) (scanrun.RunStatus, bool, error) {
	var id, status, scanID string
	err := r.db.QueryRowContext(ctx, fmt.Sprintf(splitOutcomeSQL, `p.tenant_id = $1 AND p.id = $2`),
		tenantID.String(), parentID.String()).Scan(&id, &status, &scanID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("failed to settle the split run: %w", err)
	}
	if scanID != "" {
		if err := refreshScanRunSummariesByID(ctx, r.db, []string{scanID}); err != nil {
			return scanrun.RunStatus(status), true, fmt.Errorf("split run settled, scan summary not refreshed: %w", err)
		}
	}
	return scanrun.RunStatus(status), true, nil
}

// SettleSplitParents settles every open parent whose children all finished.
func (r *ScanRunRepository) SettleSplitParents(ctx context.Context) (int64, error) {
	rows, err := r.db.QueryContext(ctx, fmt.Sprintf(splitOutcomeSQL, `p.parent_run_id IS NULL AND EXISTS (
		SELECT 1 FROM scan_runs x WHERE x.tenant_id = p.tenant_id AND x.parent_run_id = p.id)`))
	if err != nil {
		return 0, fmt.Errorf("failed to settle split runs: %w", err)
	}
	defer rows.Close()
	var n int64
	var scanIDs []string
	for rows.Next() {
		var id, status, scanID string
		if err := rows.Scan(&id, &status, &scanID); err != nil {
			return n, fmt.Errorf("failed to scan settled split run: %w", err)
		}
		n++
		if scanID != "" {
			scanIDs = append(scanIDs, scanID)
		}
	}
	if err := rows.Err(); err != nil {
		return n, fmt.Errorf("failed to iterate settled split runs: %w", err)
	}
	if len(scanIDs) > 0 {
		if err := refreshScanRunSummariesByID(ctx, r.db, scanIDs); err != nil {
			return n, fmt.Errorf("split runs settled, scan summaries not refreshed: %w", err)
		}
	}
	return n, nil
}
