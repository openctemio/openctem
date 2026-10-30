package postgres

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Batch reads behind the scan list's "Last run" and "Type" columns: one query
// per page of scans, never one per row.

func uuidStrings(ids []shared.ID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

// ListByTenantAndIDs returns the runs in ids that belong to tenantID, in one
// query. A run of another tenant is simply absent.
func (r *ScanRunRepository) ListByTenantAndIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]*scanrun.Run, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, r.selectQuery()+` WHERE tenant_id = $1 AND id = ANY($2::uuid[])`,
		tenantID.String(), pq.Array(uuidStrings(ids)))
	if err != nil {
		return nil, fmt.Errorf("failed to list runs by id: %w", err)
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

// RecentByScans returns the latest limit runs of each scan in scanIDs that
// belongs to tenantID, newest first, in one query (a LATERAL top-N per scan
// on the scan_id index). Runs of another tenant are never read: both the
// scan and the run must carry tenantID.
func (r *ScanRunRepository) RecentByScans(ctx context.Context, tenantID shared.ID, scanIDs []shared.ID, limit int) (map[shared.ID][]scanrun.RecentRun, error) {
	out := make(map[shared.ID][]scanrun.RecentRun, len(scanIDs))
	if len(scanIDs) == 0 || limit <= 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT s.id, x.id, x.status, COALESCE(x.refusal_code, ''), x.created_at
		FROM unnest($2::uuid[]) AS s(id)
		CROSS JOIN LATERAL (
			SELECT id, status, refusal_code, created_at
			FROM scan_runs
			WHERE tenant_id = $1 AND scan_id = s.id
			ORDER BY created_at DESC, id DESC
			LIMIT $3
		) x
		ORDER BY s.id, x.created_at DESC, x.id DESC`,
		tenantID.String(), pq.Array(uuidStrings(scanIDs)), limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list recent runs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var scanID, runID, status, refusal string
		var rr scanrun.RecentRun
		if err := rows.Scan(&scanID, &runID, &status, &refusal, &rr.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan recent run: %w", err)
		}
		sid, err := shared.IDFromString(scanID)
		if err != nil {
			return nil, fmt.Errorf("failed to parse scan id: %w", err)
		}
		if rr.ID, err = shared.IDFromString(runID); err != nil {
			return nil, fmt.Errorf("failed to parse run id: %w", err)
		}
		rr.Status = scanrun.RunStatus(status)
		rr.RefusalCode = refusal
		out[sid] = append(out[sid], rr)
	}
	return out, rows.Err()
}

// TemplateNames returns the names of the templates in ids that tenantID may
// use (its own and the system templates), in one query.
func (r *ScanWorkflowRepository) TemplateNames(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]string, error) {
	out := make(map[shared.ID]string, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, name FROM scan_workflows
		 WHERE id = ANY($2::uuid[]) AND (tenant_id = $1 OR is_system_template = true)`,
		tenantID.String(), pq.Array(uuidStrings(ids)))
	if err != nil {
		return nil, fmt.Errorf("failed to name templates: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, fmt.Errorf("failed to scan template name: %w", err)
		}
		if tid, err := shared.IDFromString(id); err == nil {
			out[tid] = name
		}
	}
	return out, rows.Err()
}
