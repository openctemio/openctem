package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/compliance"
	"github.com/openctemio/api/pkg/domain/shared"
)

// ComplianceMappingRepository handles finding-to-control mapping persistence.
type ComplianceMappingRepository struct {
	db *DB
}

// NewComplianceMappingRepository creates a new ComplianceMappingRepository.
func NewComplianceMappingRepository(db *DB) *ComplianceMappingRepository {
	return &ComplianceMappingRepository{db: db}
}

const mappingColumns = `id, tenant_id, finding_id, control_id, impact, notes, created_at, created_by`

// Create persists a new mapping.
func (r *ComplianceMappingRepository) Create(ctx context.Context, m *compliance.FindingControlMapping) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO compliance_finding_mappings (`+mappingColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		m.ID().String(), m.TenantID().String(), m.FindingID().String(), m.ControlID().String(),
		string(m.Impact()), m.Notes(), m.CreatedAt(), nullIDPtr(m.CreatedBy()),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return compliance.ErrMappingAlreadyExists
		}
		return fmt.Errorf("failed to create mapping: %w", err)
	}
	return nil
}

// Delete removes a mapping by ID with tenant isolation.
func (r *ComplianceMappingRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	result, err := r.db.ExecContext(ctx,
		`DELETE FROM compliance_finding_mappings WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String(),
	)
	if err != nil {
		return fmt.Errorf("failed to delete mapping: %w", err)
	}
	rows, rowErr := result.RowsAffected()
	if rowErr != nil {
		return fmt.Errorf("rows affected: %w", rowErr)
	}
	if rows == 0 {
		return compliance.ErrMappingNotFound
	}
	return nil
}

// ListByFinding lists all control mappings for a finding.
func (r *ComplianceMappingRepository) ListByFinding(ctx context.Context, tenantID, findingID shared.ID) ([]*compliance.FindingControlMapping, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+mappingColumns+` FROM compliance_finding_mappings WHERE tenant_id = $1 AND finding_id = $2 ORDER BY created_at ASC LIMIT 1000`,
		tenantID.String(), findingID.String(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list mappings by finding: %w", err)
	}
	defer rows.Close()

	mappings := make([]*compliance.FindingControlMapping, 0)
	for rows.Next() {
		m, err := r.scanMapping(rows.Scan)
		if err != nil {
			return nil, err
		}
		mappings = append(mappings, m)
	}
	return mappings, rows.Err()
}

// ListByControl lists all finding mappings for a control.
func (r *ComplianceMappingRepository) ListByControl(ctx context.Context, tenantID, controlID shared.ID) ([]*compliance.FindingControlMapping, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+mappingColumns+` FROM compliance_finding_mappings WHERE tenant_id = $1 AND control_id = $2 ORDER BY created_at ASC LIMIT 1000`,
		tenantID.String(), controlID.String(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list mappings by control: %w", err)
	}
	defer rows.Close()

	mappings := make([]*compliance.FindingControlMapping, 0)
	for rows.Next() {
		m, err := r.scanMapping(rows.Scan)
		if err != nil {
			return nil, err
		}
		mappings = append(mappings, m)
	}
	return mappings, rows.Err()
}

func (r *ComplianceMappingRepository) scanMapping(scan func(dest ...any) error) (*compliance.FindingControlMapping, error) {
	var (
		idStr, tenantIDStr, findingIDStr, controlIDStr string
		impact                                         string
		notes                                          sql.NullString
		createdAt                                      time.Time
		createdByStr                                   sql.NullString
	)

	err := scan(&idStr, &tenantIDStr, &findingIDStr, &controlIDStr, &impact, &notes, &createdAt, &createdByStr)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, compliance.ErrMappingNotFound
		}
		return nil, err
	}

	id, _ := shared.IDFromString(idStr)
	tenantID, _ := shared.IDFromString(tenantIDStr)
	findingID, _ := shared.IDFromString(findingIDStr)
	controlID, _ := shared.IDFromString(controlIDStr)

	var createdBy *shared.ID
	if createdByStr.Valid {
		cb, _ := shared.IDFromString(createdByStr.String)
		createdBy = &cb
	}

	return compliance.ReconstituteFindingControlMapping(
		id, tenantID, findingID, controlID,
		compliance.ImpactType(impact), notes.String, createdAt, createdBy,
	), nil
}

// isUniqueViolation is defined in helpers.go
