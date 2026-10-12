package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ scanrun.StallRepairStore = (*ScanRunRepository)(nil)

// ReleaseOrphanStagePlans deletes the stage plans a crash left between
// saving the plan and creating its commands.
func (r *ScanRunRepository) ReleaseOrphanStagePlans(ctx context.Context, olderThan time.Time, limit int) (int64, error) {
	if limit <= 0 {
		limit = 100
	}
	res, err := r.db.ExecContext(ctx, `
		WITH orphan AS (
			SELECT p.tenant_id, p.run_id, p.stage_key
			FROM scan_run_stage_plans p
			JOIN scan_runs r ON r.id = p.run_id AND r.tenant_id = p.tenant_id AND r.status = 'running'
			JOIN scan_run_steps s ON s.scan_run_id = p.run_id AND s.step_key = p.stage_key AND s.status = 'pending'
			WHERE p.planned_at < $1
			  AND NOT EXISTS (SELECT 1 FROM commands c WHERE c.tenant_id = p.tenant_id AND c.scan_run_step_id = s.id)
			LIMIT $2
		), released_targets AS (
			DELETE FROM scan_run_targets t USING orphan o
			WHERE t.tenant_id = o.tenant_id AND t.run_id = o.run_id AND t.stage_key = o.stage_key
		)
		DELETE FROM scan_run_stage_plans p USING orphan o
		WHERE p.tenant_id = o.tenant_id AND p.run_id = o.run_id AND p.stage_key = o.stage_key`,
		olderThan, limit)
	if err != nil {
		return 0, fmt.Errorf("release orphan stage plans: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// StalledRuns returns running workflow runs that wait on nothing.
func (r *ScanRunRepository) StalledRuns(ctx context.Context, quietSince time.Time, limit int) ([]scanrun.StalledRun, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT r.tenant_id, r.id
		FROM scan_runs r
		WHERE r.status = 'running'
		  AND COALESCE(r.started_at, r.created_at) < $1
		  AND EXISTS (SELECT 1 FROM scan_run_steps s WHERE s.scan_run_id = r.id AND s.status = 'pending')
		  AND NOT EXISTS (SELECT 1 FROM scan_run_steps s WHERE s.scan_run_id = r.id
		                  AND (s.status IN ('queued', 'running')
		                       OR COALESCE(s.completed_at, s.started_at, s.queued_at, s.created_at) >= $1))
		  AND NOT EXISTS (SELECT 1 FROM ingest_reports ir
		                  JOIN commands c ON c.id = ir.command_id AND c.tenant_id = ir.tenant_id
		                  JOIN scan_run_steps s ON s.id = c.scan_run_step_id
		                  WHERE s.scan_run_id = r.id AND ir.tenant_id = r.tenant_id
		                    AND ir.state IN ('receiving', 'queued', 'processing'))
		ORDER BY COALESCE(r.started_at, r.created_at)
		LIMIT $2`, quietSince, limit)
	if err != nil {
		return nil, fmt.Errorf("find stalled runs: %w", err)
	}
	defer rows.Close()
	var out []scanrun.StalledRun
	for rows.Next() {
		var tenant, run string
		if err := rows.Scan(&tenant, &run); err != nil {
			return nil, fmt.Errorf("scan stalled run: %w", err)
		}
		tid, terr := shared.IDFromString(tenant)
		rid, rerr := shared.IDFromString(run)
		if terr != nil || rerr != nil {
			continue
		}
		out = append(out, scanrun.StalledRun{TenantID: tid, RunID: rid})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("find stalled runs: %w", err)
	}
	return out, nil
}
