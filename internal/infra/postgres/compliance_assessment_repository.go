package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
	"github.com/openctemio/api/pkg/domain/compliance"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// ComplianceAssessmentRepository handles compliance assessment persistence.
type ComplianceAssessmentRepository struct {
	db *DB
}

// NewComplianceAssessmentRepository creates a new ComplianceAssessmentRepository.
func NewComplianceAssessmentRepository(db *DB) *ComplianceAssessmentRepository {
	return &ComplianceAssessmentRepository{db: db}
}

const assessmentColumns = `id, tenant_id, framework_id, control_id, status, priority, owner,
	notes, evidence_type, evidence_ids, evidence_count, finding_count,
	assessed_by, assessed_at, due_date, created_at, updated_at`

// GetByTenantAndControl retrieves an assessment by tenant and control.
func (r *ComplianceAssessmentRepository) GetByTenantAndControl(ctx context.Context, tenantID, controlID shared.ID) (*compliance.Assessment, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+assessmentColumns+` FROM compliance_assessments WHERE tenant_id = $1 AND control_id = $2`,
		tenantID.String(), controlID.String(),
	)
	a, err := r.scanAssessment(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, compliance.ErrAssessmentNotFound
		}
		return nil, fmt.Errorf("failed to get assessment: %w", err)
	}
	return a, nil
}

// Upsert creates or updates an assessment.
func (r *ComplianceAssessmentRepository) Upsert(ctx context.Context, a *compliance.Assessment) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO compliance_assessments (`+assessmentColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
		ON CONFLICT (tenant_id, control_id) DO UPDATE SET
			status = EXCLUDED.status, priority = EXCLUDED.priority, owner = EXCLUDED.owner,
			notes = EXCLUDED.notes, evidence_type = EXCLUDED.evidence_type,
			evidence_ids = EXCLUDED.evidence_ids, evidence_count = EXCLUDED.evidence_count,
			finding_count = EXCLUDED.finding_count, assessed_by = EXCLUDED.assessed_by,
			assessed_at = EXCLUDED.assessed_at, due_date = EXCLUDED.due_date, updated_at = EXCLUDED.updated_at`,
		a.ID().String(), a.TenantID().String(), a.FrameworkID().String(), a.ControlID().String(),
		string(a.Status()), nullString(string(a.Priority())), a.Owner(),
		a.Notes(), nullString(string(a.EvidenceType())),
		pq.StringArray(a.EvidenceIDs()), a.EvidenceCount(), a.FindingCount(),
		nullIDPtr(a.AssessedBy()), a.AssessedAt(), nullTime(a.DueDate()),
		a.CreatedAt(), a.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to upsert assessment: %w", err)
	}
	return nil
}

// ListByFramework lists assessments for a framework.
func (r *ComplianceAssessmentRepository) ListByFramework(ctx context.Context, tenantID, frameworkID shared.ID, page pagination.Pagination) (pagination.Result[*compliance.Assessment], error) {
	where := ` WHERE tenant_id = $1 AND framework_id = $2`
	args := []any{tenantID.String(), frameworkID.String()}

	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM compliance_assessments`+where, args...).Scan(&total); err != nil {
		return pagination.Result[*compliance.Assessment]{}, fmt.Errorf("failed to count assessments: %w", err)
	}

	query := `SELECT ` + assessmentColumns + ` FROM compliance_assessments` + where +
		fmt.Sprintf(` ORDER BY created_at ASC LIMIT $%d OFFSET $%d`, len(args)+1, len(args)+2)
	args = append(args, page.Limit(), page.Offset())

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*compliance.Assessment]{}, fmt.Errorf("failed to list assessments: %w", err)
	}
	defer rows.Close()

	assessments := make([]*compliance.Assessment, 0)
	for rows.Next() {
		a, err := r.scanAssessment(rows.Scan)
		if err != nil {
			return pagination.Result[*compliance.Assessment]{}, err
		}
		assessments = append(assessments, a)
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[*compliance.Assessment]{}, fmt.Errorf("failed to iterate assessments: %w", err)
	}

	return pagination.NewResult(assessments, total, page), nil
}

// GetStatsByFramework returns compliance stats for a framework.
func (r *ComplianceAssessmentRepository) GetStatsByFramework(ctx context.Context, tenantID, frameworkID shared.ID) (*compliance.FrameworkStats, error) {
	query := `
		SELECT
			(SELECT total_controls FROM compliance_frameworks WHERE id = $2) as total,
			COUNT(*) FILTER (WHERE a.status = 'implemented') as implemented,
			COUNT(*) FILTER (WHERE a.status = 'partial') as partial,
			COUNT(*) FILTER (WHERE a.status = 'not_implemented') as not_implemented,
			COUNT(*) FILTER (WHERE a.status = 'not_applicable') as not_applicable,
			COUNT(*) FILTER (WHERE a.status = 'not_assessed' OR a.status IS NULL) as not_assessed
		FROM compliance_controls c
		LEFT JOIN compliance_assessments a ON c.id = a.control_id AND a.tenant_id = $1
		WHERE c.framework_id = $2`

	stats := &compliance.FrameworkStats{}
	err := r.db.QueryRowContext(ctx, query, tenantID.String(), frameworkID.String()).Scan(
		&stats.TotalControls, &stats.Implemented, &stats.Partial,
		&stats.NotImplemented, &stats.NotApplicable, &stats.NotAssessed,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get framework stats: %w", err)
	}
	return stats, nil
}

// GetOverdueCount returns count of overdue assessments.
func (r *ComplianceAssessmentRepository) GetOverdueCount(ctx context.Context, tenantID shared.ID) (int64, error) {
	var count int64
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM compliance_assessments
		WHERE tenant_id = $1 AND due_date IS NOT NULL AND due_date < NOW()
		AND status NOT IN ('implemented', 'not_applicable')`,
		tenantID.String(),
	).Scan(&count)
	return count, err
}

func (r *ComplianceAssessmentRepository) scanAssessment(scan func(dest ...any) error) (*compliance.Assessment, error) {
	var (
		idStr, tenantIDStr, frameworkIDStr, controlIDStr string
		status                                          string
		priority, owner, notes                          sql.NullString
		evidenceType                                    sql.NullString
		evidenceIDs                                     []string
		evidenceCount, findingCount                     int
		assessedByStr                                   sql.NullString
		assessedAt, dueDate                             sql.NullTime
		createdAt, updatedAt                            time.Time
	)

	err := scan(
		&idStr, &tenantIDStr, &frameworkIDStr, &controlIDStr,
		&status, &priority, &owner,
		&notes, &evidenceType,
		(*pq.StringArray)(&evidenceIDs), &evidenceCount, &findingCount,
		&assessedByStr, &assessedAt, &dueDate,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	id, _ := shared.IDFromString(idStr)
	tenantID, _ := shared.IDFromString(tenantIDStr)
	frameworkID, _ := shared.IDFromString(frameworkIDStr)
	controlID, _ := shared.IDFromString(controlIDStr)

	var assessedBy *shared.ID
	if assessedByStr.Valid {
		ab, _ := shared.IDFromString(assessedByStr.String)
		assessedBy = &ab
	}

	var at *time.Time
	if assessedAt.Valid {
		at = &assessedAt.Time
	}
	var dd *time.Time
	if dueDate.Valid {
		dd = &dueDate.Time
	}

	return compliance.ReconstituteAssessment(
		id, tenantID, frameworkID, controlID,
		compliance.ControlStatus(status), compliance.Priority(priority.String),
		owner.String, notes.String, compliance.EvidenceType(evidenceType.String),
		evidenceIDs, evidenceCount, findingCount,
		assessedBy, at, dd, createdAt, updatedAt,
	), nil
}
