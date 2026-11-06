package postgres

// Lineage of tenant copies of system scan workflows (template updates;
// migration workflow_template_lineage).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ scanworkflow.LineageStore = (*ScanWorkflowRepository)(nil)

// GetLineage returns the tenant's copy's lineage; nil when it has none or
// the workflow is not the tenant's.
func (r *ScanWorkflowRepository) GetLineage(ctx context.Context, tenantID, workflowID shared.ID) (*scanworkflow.Lineage, error) {
	var src sql.NullString
	var raw []byte
	err := r.db.QueryRowContext(ctx, `
		SELECT source_template_id, source_spec FROM scan_workflows
		 WHERE tenant_id = $1 AND id = $2 AND NOT is_system_template`,
		tenantID.String(), workflowID.String()).Scan(&src, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read scan workflow lineage: %w", err)
	}
	if !src.Valid {
		return nil, nil
	}
	id, err := shared.IDFromString(src.String)
	if err != nil {
		return nil, fmt.Errorf("read scan workflow lineage: %w", err)
	}
	l := &scanworkflow.Lineage{SourceTemplateID: id}
	if len(raw) > 0 {
		var spec scanworkflow.Spec
		if err := json.Unmarshal(raw, &spec); err != nil {
			return nil, fmt.Errorf("read scan workflow lineage: %w", err)
		}
		l.Base = &spec
	}
	return l, nil
}

// SetLineage records the copy's source and base. Only the tenant's own
// (non-system) workflow is written, and the source must be a system
// template; anything else is not found.
func (r *ScanWorkflowRepository) SetLineage(ctx context.Context, tenantID, workflowID, sourceTemplateID shared.ID, base scanworkflow.Spec) error {
	raw, err := json.Marshal(base)
	if err != nil {
		return fmt.Errorf("encode scan workflow lineage: %w", err)
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE scan_workflows w SET source_template_id = $3, source_spec = $4
		 WHERE w.tenant_id = $1 AND w.id = $2 AND NOT w.is_system_template
		   AND EXISTS (SELECT 1 FROM scan_workflows s WHERE s.id = $3 AND s.is_system_template)`,
		tenantID.String(), workflowID.String(), sourceTemplateID.String(), raw)
	if err != nil {
		return fmt.Errorf("write scan workflow lineage: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return shared.ErrNotFound
	}
	return nil
}
