package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/openctemio/api/internal/app/validation"
	"github.com/openctemio/api/pkg/domain/shared"
)

// ValidationEvidenceRepository persists CTEM Stage-4 validation evidence
// (proof-of-fix / technique-execution results) into the validation_evidence
// table. It implements validation.EvidenceRepository.
type ValidationEvidenceRepository struct {
	db *DB
}

// NewValidationEvidenceRepository creates the repository.
func NewValidationEvidenceRepository(db *DB) *ValidationEvidenceRepository {
	return &ValidationEvidenceRepository{db: db}
}

// Create inserts one evidence row. The full (already-redacted) Evidence envelope
// is stored as JSONB; key fields are denormalised into columns for querying.
func (r *ValidationEvidenceRepository) Create(ctx context.Context, ev validation.StoredEvidence) error {
	payload, err := json.Marshal(ev.Evidence)
	if err != nil {
		return fmt.Errorf("marshal evidence: %w", err)
	}

	var simRunID sql.NullString
	if ev.SimulationRunID != nil && !ev.SimulationRunID.IsZero() {
		simRunID = sql.NullString{String: ev.SimulationRunID.String(), Valid: true}
	}

	const q = `
		INSERT INTO validation_evidence
		       (id, tenant_id, finding_id, simulation_run_id, executor_kind, technique, outcome, summary, evidence, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err = r.db.ExecContext(ctx, q,
		ev.ID.String(),
		ev.TenantID.String(),
		ev.FindingID.String(),
		simRunID,
		ev.Evidence.ExecutorKind,
		string(ev.Evidence.Technique),
		string(ev.Evidence.Outcome),
		ev.Evidence.Summary,
		payload,
		ev.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert validation evidence: %w", err)
	}
	return nil
}

// ListByFinding returns every evidence row for a finding, newest first, scoped
// to the tenant.
func (r *ValidationEvidenceRepository) ListByFinding(ctx context.Context, tenantID, findingID shared.ID) ([]validation.StoredEvidence, error) {
	const q = `
		SELECT id, tenant_id, finding_id, simulation_run_id, evidence, created_at
		  FROM validation_evidence
		 WHERE tenant_id = $1 AND finding_id = $2
		 ORDER BY created_at DESC
	`
	rows, err := r.db.QueryContext(ctx, q, tenantID.String(), findingID.String())
	if err != nil {
		return nil, fmt.Errorf("query validation evidence: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []validation.StoredEvidence
	for rows.Next() {
		var (
			idStr, tenantStr, findingStr string
			simRunID                     sql.NullString
			payload                      []byte
			stored                       validation.StoredEvidence
		)
		if err := rows.Scan(&idStr, &tenantStr, &findingStr, &simRunID, &payload, &stored.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan validation evidence: %w", err)
		}

		if stored.ID, err = shared.IDFromString(idStr); err != nil {
			return nil, fmt.Errorf("parse evidence id: %w", err)
		}
		if stored.TenantID, err = shared.IDFromString(tenantStr); err != nil {
			return nil, fmt.Errorf("parse tenant id: %w", err)
		}
		if stored.FindingID, err = shared.IDFromString(findingStr); err != nil {
			return nil, fmt.Errorf("parse finding id: %w", err)
		}
		if simRunID.Valid {
			runID, perr := shared.IDFromString(simRunID.String)
			if perr != nil {
				return nil, fmt.Errorf("parse simulation_run_id: %w", perr)
			}
			stored.SimulationRunID = &runID
		}
		if err := json.Unmarshal(payload, &stored.Evidence); err != nil {
			return nil, fmt.Errorf("unmarshal evidence: %w", err)
		}
		out = append(out, stored)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate validation evidence: %w", err)
	}
	return out, nil
}
