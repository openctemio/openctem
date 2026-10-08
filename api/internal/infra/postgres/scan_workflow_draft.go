package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ scanworkflow.DraftRepository = (*ScanWorkflowRepository)(nil)

// GetDraft implements scanworkflow.DraftRepository.
func (r *ScanWorkflowRepository) GetDraft(ctx context.Context, tenantID, workflowID shared.ID) (*scanworkflow.Draft, error) {
	var d scanworkflow.Draft
	var spec, issues []byte
	var updated sql.NullTime
	err := r.db.QueryRowContext(ctx, `
		SELECT draft, draft_issues, draft_updated_at
		FROM scan_workflows
		WHERE id = $1 AND tenant_id = $2 AND draft IS NOT NULL`,
		workflowID.String(), tenantID.String()).Scan(&spec, &issues, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get scan workflow draft: %w", err)
	}
	d.Spec, d.Issues = spec, issues
	if updated.Valid {
		d.UpdatedAt = updated.Time
	}
	return &d, nil
}

// SaveDraft implements scanworkflow.DraftRepository.
func (r *ScanWorkflowRepository) SaveDraft(ctx context.Context, tenantID, workflowID shared.ID, d *scanworkflow.Draft) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE scan_workflows
		SET draft = $3, draft_issues = $4, draft_updated_at = $5
		WHERE id = $1 AND tenant_id = $2 AND NOT is_system_template`,
		workflowID.String(), tenantID.String(), []byte(d.Spec), nullBytes(d.Issues), d.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to save scan workflow draft: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return shared.ErrNotFound
	}
	return nil
}

// ClearDraft implements scanworkflow.DraftRepository.
func (r *ScanWorkflowRepository) ClearDraft(ctx context.Context, tenantID, workflowID shared.ID) error {
	if _, err := r.db.ExecContext(ctx, `
		UPDATE scan_workflows
		SET draft = NULL, draft_issues = NULL, draft_updated_at = NULL
		WHERE id = $1 AND tenant_id = $2`,
		workflowID.String(), tenantID.String()); err != nil {
		return fmt.Errorf("failed to clear scan workflow draft: %w", err)
	}
	return nil
}
