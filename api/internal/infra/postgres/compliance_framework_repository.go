package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/compliance"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// ComplianceFrameworkRepository handles compliance framework persistence.
type ComplianceFrameworkRepository struct {
	db *DB
}

// NewComplianceFrameworkRepository creates a new ComplianceFrameworkRepository.
func NewComplianceFrameworkRepository(db *DB) *ComplianceFrameworkRepository {
	return &ComplianceFrameworkRepository{db: db}
}

const frameworkColumns = `id, tenant_id, name, slug, version, description, category,
	total_controls, is_system, is_active, metadata, created_at, updated_at`

// Create persists a new framework.
func (r *ComplianceFrameworkRepository) Create(ctx context.Context, f *compliance.Framework) error {
	metaJSON, _ := json.Marshal(f.Metadata())
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO compliance_frameworks (`+frameworkColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		f.ID().String(), nullIDPtr(f.TenantID()), f.Name(), f.Slug(), f.Version(),
		f.Description(), string(f.Category()), f.TotalControls(),
		f.IsSystem(), f.IsActive(), metaJSON, f.CreatedAt(), f.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to create framework: %w", err)
	}
	return nil
}

// GetByID retrieves a framework by ID with tenant isolation.
func (r *ComplianceFrameworkRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*compliance.Framework, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+frameworkColumns+` FROM compliance_frameworks WHERE id = $1 AND (tenant_id IS NULL OR tenant_id = $2)`,
		id.String(), tenantID.String(),
	)
	f, err := r.scanFramework(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, compliance.ErrFrameworkNotFound
		}
		return nil, fmt.Errorf("failed to get framework: %w", err)
	}
	return f, nil
}

// GetBySlug retrieves a system framework by slug.
func (r *ComplianceFrameworkRepository) GetBySlug(ctx context.Context, slug string) (*compliance.Framework, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+frameworkColumns+` FROM compliance_frameworks WHERE slug = $1 AND tenant_id IS NULL`, slug,
	)
	f, err := r.scanFramework(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, compliance.ErrFrameworkNotFound
		}
		return nil, fmt.Errorf("failed to get framework by slug: %w", err)
	}
	return f, nil
}

// Update persists framework changes with tenant isolation.
func (r *ComplianceFrameworkRepository) Update(ctx context.Context, tenantID shared.ID, f *compliance.Framework) error {
	metaJSON, _ := json.Marshal(f.Metadata())
	result, err := r.db.ExecContext(ctx,
		`UPDATE compliance_frameworks SET name=$3, slug=$4, version=$5, description=$6,
			category=$7, total_controls=$8, is_active=$9, metadata=$10, updated_at=$11
		WHERE id=$1 AND tenant_id = $2 AND is_system = FALSE`,
		f.ID().String(), tenantID.String(), f.Name(), f.Slug(), f.Version(), f.Description(),
		string(f.Category()), f.TotalControls(), f.IsActive(), metaJSON, f.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to update framework: %w", err)
	}
	rows, rowErr := result.RowsAffected()
	if rowErr != nil {
		return fmt.Errorf("rows affected: %w", rowErr)
	}
	if rows == 0 {
		return compliance.ErrFrameworkNotFound
	}
	return nil
}

// Delete removes a framework with tenant isolation.
func (r *ComplianceFrameworkRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	result, err := r.db.ExecContext(ctx,
		`DELETE FROM compliance_frameworks WHERE id = $1 AND tenant_id = $2 AND is_system = FALSE`,
		id.String(), tenantID.String(),
	)
	if err != nil {
		return fmt.Errorf("failed to delete framework: %w", err)
	}
	rows, rowErr := result.RowsAffected()
	if rowErr != nil {
		return fmt.Errorf("rows affected: %w", rowErr)
	}
	if rows == 0 {
		return compliance.ErrFrameworkNotFound
	}
	return nil
}

// List retrieves frameworks with filtering.
func (r *ComplianceFrameworkRepository) List(ctx context.Context, filter compliance.FrameworkFilter, page pagination.Pagination) (pagination.Result[*compliance.Framework], error) {
	where, args := r.buildFrameworkWhere(filter)

	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM compliance_frameworks`+where, args...).Scan(&total); err != nil {
		return pagination.Result[*compliance.Framework]{}, fmt.Errorf("failed to count frameworks: %w", err)
	}

	query := `SELECT ` + frameworkColumns + ` FROM compliance_frameworks` + where +
		fmt.Sprintf(` ORDER BY is_system DESC, name ASC LIMIT $%d OFFSET $%d`, len(args)+1, len(args)+2)
	args = append(args, page.Limit(), page.Offset())

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*compliance.Framework]{}, fmt.Errorf("failed to list frameworks: %w", err)
	}
	defer rows.Close()

	frameworks := make([]*compliance.Framework, 0)
	for rows.Next() {
		f, err := r.scanFramework(rows.Scan)
		if err != nil {
			return pagination.Result[*compliance.Framework]{}, err
		}
		frameworks = append(frameworks, f)
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[*compliance.Framework]{}, fmt.Errorf("failed to iterate frameworks: %w", err)
	}
	return pagination.NewResult(frameworks, total, page), nil
}

func (r *ComplianceFrameworkRepository) scanFramework(scan func(dest ...any) error) (*compliance.Framework, error) {
	var (
		idStr, name, slug, version, description string
		tenantIDStr                             sql.NullString
		category                                string
		totalControls                           int
		isSystem, isActive                      bool
		metaJSON                                []byte
		createdAt, updatedAt                    time.Time
	)

	err := scan(&idStr, &tenantIDStr, &name, &slug, &version, &description, &category,
		&totalControls, &isSystem, &isActive, &metaJSON, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}

	id, _ := shared.IDFromString(idStr)
	var tenantID *shared.ID
	if tenantIDStr.Valid {
		tid, _ := shared.IDFromString(tenantIDStr.String)
		tenantID = &tid
	}

	var meta map[string]any
	if len(metaJSON) > 0 {
		_ = json.Unmarshal(metaJSON, &meta)
	}

	return compliance.ReconstituteFramework(
		id, tenantID, name, slug, version, description,
		compliance.FrameworkCategory(category), totalControls, isSystem, isActive, meta,
		createdAt, updatedAt,
	), nil
}

func (r *ComplianceFrameworkRepository) buildFrameworkWhere(filter compliance.FrameworkFilter) (string, []any) {
	var conditions []string
	var args []any
	idx := 1

	// Show system frameworks + tenant frameworks
	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("(tenant_id IS NULL OR tenant_id = $%d)", idx))
		args = append(args, filter.TenantID.String())
		idx++
	}
	if filter.Category != nil {
		conditions = append(conditions, fmt.Sprintf("category = $%d", idx))
		args = append(args, string(*filter.Category))
		idx++
	}
	if filter.IsSystem != nil {
		conditions = append(conditions, fmt.Sprintf("is_system = $%d", idx))
		args = append(args, *filter.IsSystem)
		idx++
	}
	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if filter.Search != nil && *filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", idx, idx))
		args = append(args, wrapLikePattern(*filter.Search))
		idx++
	}

	// Always show active frameworks by default
	if filter.IsActive == nil {
		conditions = append(conditions, "is_active = TRUE")
	}

	if len(conditions) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conditions, " AND "), args
}
