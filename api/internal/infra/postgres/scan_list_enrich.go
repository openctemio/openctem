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
