package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ scanworkflow.VersionStore = (*ScanWorkflowRepository)(nil)

// PinVersion saves spec as the next version of the workflow unless the
// latest version has the same digest, and returns the version a run is
// pinned to. The workflow is the tenant's own or a shared system template
// (a starter workflow any tenant runs); a system template's versions belong
// to the template's owner and are shared like the template. The workflow
// row is locked for the transaction, so two runs starting together never
// save the same version twice.
func (r *ScanWorkflowRepository) PinVersion(ctx context.Context, tenantID, workflowID shared.ID, spec scanworkflow.Spec) (int, string, error) {
	digest, err := spec.Digest()
	if err != nil {
		return 0, "", fmt.Errorf("digest scan workflow spec: %w", err)
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		return 0, "", fmt.Errorf("marshal scan workflow spec: %w", err)
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, "", fmt.Errorf("begin pin version: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var owner string
	err = tx.QueryRowContext(ctx,
		`SELECT tenant_id FROM scan_workflows
		 WHERE id = $1 AND (tenant_id = $2 OR is_system_template = TRUE) FOR UPDATE`,
		workflowID.String(), tenantID.String()).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", shared.ErrNotFound
	}
	if err != nil {
		return 0, "", fmt.Errorf("lock scan workflow: %w", err)
	}

	var latest int
	var latestDigest sql.NullString
	err = tx.QueryRowContext(ctx, `
		SELECT version, spec_digest FROM scan_workflow_versions
		WHERE scan_workflow_id = $1 AND tenant_id = $2
		ORDER BY version DESC LIMIT 1`,
		workflowID.String(), owner).Scan(&latest, &latestDigest)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, "", fmt.Errorf("read latest scan workflow version: %w", err)
	}
	if latest > 0 && latestDigest.String == digest {
		return latest, digest, nil
	}

	next := latest + 1
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO scan_workflow_versions (tenant_id, scan_workflow_id, version, spec, spec_digest)
		VALUES ($1, $2, $3, $4, $5)`,
		owner, workflowID.String(), next, raw, digest); err != nil {
		return 0, "", fmt.Errorf("save scan workflow version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, "", fmt.Errorf("commit pin version: %w", err)
	}
	return next, digest, nil
}

// GetVersion returns a saved version of the tenant's workflow or of a shared
// system template. Another tenant's private workflow is not found.
func (r *ScanWorkflowRepository) GetVersion(ctx context.Context, tenantID, workflowID shared.ID, version int) (*scanworkflow.Spec, error) {
	var raw []byte
	err := r.db.QueryRowContext(ctx, `
		SELECT v.spec FROM scan_workflow_versions v
		JOIN scan_workflows w ON w.id = v.scan_workflow_id AND w.tenant_id = v.tenant_id
		WHERE v.scan_workflow_id = $1 AND v.version = $3
		  AND (v.tenant_id = $2 OR w.is_system_template = TRUE)`,
		workflowID.String(), tenantID.String(), version).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get scan workflow version: %w", err)
	}
	var spec scanworkflow.Spec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return nil, fmt.Errorf("decode scan workflow version: %w", err)
	}
	return &spec, nil
}
