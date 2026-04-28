package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/compliance"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// ComplianceControlRepository handles compliance control persistence.
type ComplianceControlRepository struct {
	db *DB
}

// NewComplianceControlRepository creates a new ComplianceControlRepository.
func NewComplianceControlRepository(db *DB) *ComplianceControlRepository {
	return &ComplianceControlRepository{db: db}
}

const controlColumns = `id, framework_id, control_id, title, description, category,
	parent_control_id, sort_order, metadata, created_at`

// Create persists a new control.
func (r *ComplianceControlRepository) Create(ctx context.Context, c *compliance.Control) error {
	metaJSON, _ := json.Marshal(c.Metadata())
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO compliance_controls (`+controlColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		c.ID().String(), c.FrameworkID().String(), c.ControlID(), c.Title(), c.Description(),
		c.Category(), nullIDPtr(c.ParentControlID()), c.SortOrder(), metaJSON, c.CreatedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to create control: %w", err)
	}
	return nil
}

// GetByID retrieves a control by ID.
//
//getbyid:unsafe - Compliance controls are a shared catalog; no tenant_id column.
func (r *ComplianceControlRepository) GetByID(ctx context.Context, id shared.ID) (*compliance.Control, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+controlColumns+` FROM compliance_controls WHERE id = $1`, id.String())
	c, err := r.scanControl(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, compliance.ErrControlNotFound
		}
		return nil, fmt.Errorf("failed to get control: %w", err)
	}
	return c, nil
}

// ListByFramework retrieves controls for a framework.
func (r *ComplianceControlRepository) ListByFramework(ctx context.Context, frameworkID shared.ID, page pagination.Pagination) (pagination.Result[*compliance.Control], error) {
	var total int64
	if err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM compliance_controls WHERE framework_id = $1`, frameworkID.String(),
	).Scan(&total); err != nil {
		return pagination.Result[*compliance.Control]{}, fmt.Errorf("failed to count controls: %w", err)
	}

	query := `SELECT ` + controlColumns + ` FROM compliance_controls WHERE framework_id = $1
		ORDER BY sort_order ASC, control_id ASC LIMIT $2 OFFSET $3`

	rows, err := r.db.QueryContext(ctx, query, frameworkID.String(), page.Limit(), page.Offset())
	if err != nil {
		return pagination.Result[*compliance.Control]{}, fmt.Errorf("failed to list controls: %w", err)
	}
	defer rows.Close()

	controls := make([]*compliance.Control, 0)
	for rows.Next() {
		c, err := r.scanControl(rows.Scan)
		if err != nil {
			return pagination.Result[*compliance.Control]{}, err
		}
		controls = append(controls, c)
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[*compliance.Control]{}, fmt.Errorf("failed to iterate controls: %w", err)
	}
	return pagination.NewResult(controls, total, page), nil
}

// CountByFramework returns the number of controls in a framework.
func (r *ComplianceControlRepository) CountByFramework(ctx context.Context, frameworkID shared.ID) (int64, error) {
	var count int64
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM compliance_controls WHERE framework_id = $1`, frameworkID.String(),
	).Scan(&count)
	return count, err
}

func (r *ComplianceControlRepository) scanControl(scan func(dest ...any) error) (*compliance.Control, error) {
	var (
		idStr, frameworkIDStr, controlID, title string
		description, category                  sql.NullString
		parentControlIDStr                     sql.NullString
		sortOrder                              int
		metaJSON                               []byte
		createdAt                              time.Time
	)

	err := scan(&idStr, &frameworkIDStr, &controlID, &title, &description, &category,
		&parentControlIDStr, &sortOrder, &metaJSON, &createdAt)
	if err != nil {
		return nil, err
	}

	id, _ := shared.IDFromString(idStr)
	frameworkID, _ := shared.IDFromString(frameworkIDStr)

	var parentID *shared.ID
	if parentControlIDStr.Valid {
		pid, _ := shared.IDFromString(parentControlIDStr.String)
		parentID = &pid
	}

	var meta map[string]any
	if len(metaJSON) > 0 {
		_ = json.Unmarshal(metaJSON, &meta)
	}

	return compliance.ReconstituteControl(
		id, frameworkID, controlID, title, description.String, category.String,
		parentID, sortOrder, meta, createdAt,
	), nil
}
