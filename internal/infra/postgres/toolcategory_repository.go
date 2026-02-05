package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/toolcategory"
	"github.com/openctemio/api/pkg/pagination"
)

// ToolCategoryRepository implements toolcategory.Repository using PostgreSQL.
type ToolCategoryRepository struct {
	db *DB
}

// NewToolCategoryRepository creates a new ToolCategoryRepository.
func NewToolCategoryRepository(db *DB) *ToolCategoryRepository {
	return &ToolCategoryRepository{db: db}
}

// selectQuery returns the base SELECT query for tool categories.
func (r *ToolCategoryRepository) selectQuery() string {
	return `
		SELECT
			id, tenant_id, name, display_name, description,
			icon, color, is_builtin, sort_order,
			created_by, created_at, updated_at
		FROM tool_categories
	`
}

// scanCategory scans a single row into a ToolCategory.
func (r *ToolCategoryRepository) scanCategory(row interface{ Scan(...any) error }) (*toolcategory.ToolCategory, error) {
	var (
		id          string
		tenantID    sql.NullString
		name        string
		displayName string
		description sql.NullString
		icon        string
		color       string
		isBuiltin   bool
		sortOrder   int
		createdBy   sql.NullString
		createdAt   sql.NullTime
		updatedAt   sql.NullTime
	)

	err := row.Scan(
		&id, &tenantID, &name, &displayName, &description,
		&icon, &color, &isBuiltin, &sortOrder,
		&createdBy, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	tc := &toolcategory.ToolCategory{
		Name:        name,
		DisplayName: displayName,
		Icon:        icon,
		Color:       color,
		IsBuiltin:   isBuiltin,
		SortOrder:   sortOrder,
	}

	tc.ID, _ = shared.IDFromString(id)

	if tenantID.Valid {
		tid, _ := shared.IDFromString(tenantID.String)
		tc.TenantID = &tid
	}

	if description.Valid {
		tc.Description = description.String
	}

	if createdBy.Valid {
		cid, _ := shared.IDFromString(createdBy.String)
		tc.CreatedBy = &cid
	}

	if createdAt.Valid {
		tc.CreatedAt = createdAt.Time
	}

	if updatedAt.Valid {
		tc.UpdatedAt = updatedAt.Time
	}

	return tc, nil
}

// Create persists a new tool category.
func (r *ToolCategoryRepository) Create(ctx context.Context, tc *toolcategory.ToolCategory) error {
	// Handle nullable tenant_id
	var tenantID any
	if tc.TenantID != nil {
		tenantID = tc.TenantID.String()
	}

	// Handle nullable created_by
	var createdBy any
	if tc.CreatedBy != nil {
		createdBy = tc.CreatedBy.String()
	}

	query := `
		INSERT INTO tool_categories (
			id, tenant_id, name, display_name, description,
			icon, color, is_builtin, sort_order,
			created_by, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err := r.db.ExecContext(ctx, query,
		tc.ID.String(),
		tenantID,
		tc.Name,
		tc.DisplayName,
		tc.Description,
		tc.Icon,
		tc.Color,
		tc.IsBuiltin,
		tc.SortOrder,
		createdBy,
		tc.CreatedAt,
		tc.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: category with name '%s' already exists", shared.ErrConflict, tc.Name)
		}
		return fmt.Errorf("failed to create tool category: %w", err)
	}

	return nil
}

// GetByID returns a category by ID.
func (r *ToolCategoryRepository) GetByID(ctx context.Context, id shared.ID) (*toolcategory.ToolCategory, error) {
	query := r.selectQuery() + " WHERE id = $1"

	row := r.db.QueryRowContext(ctx, query, id.String())
	tc, err := r.scanCategory(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: tool category not found", shared.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get tool category: %w", err)
	}

	return tc, nil
}

// GetByName returns a category by name within a scope.
func (r *ToolCategoryRepository) GetByName(ctx context.Context, tenantID *shared.ID, name string) (*toolcategory.ToolCategory, error) {
	var query string
	var args []any

	if tenantID == nil {
		// Look for platform category
		query = r.selectQuery() + " WHERE tenant_id IS NULL AND name = $1"
		args = []any{name}
	} else {
		// Look for tenant category
		query = r.selectQuery() + " WHERE tenant_id = $1 AND name = $2"
		args = []any{tenantID.String(), name}
	}

	row := r.db.QueryRowContext(ctx, query, args...)
	tc, err := r.scanCategory(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: tool category not found", shared.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get tool category by name: %w", err)
	}

	return tc, nil
}

// List returns categories matching the filter with pagination.
func (r *ToolCategoryRepository) List(ctx context.Context, filter toolcategory.Filter, page pagination.Pagination) (pagination.Result[*toolcategory.ToolCategory], error) {
	var conditions []string
	var args []any
	argIdx := 1

	// Always include platform categories OR tenant's own categories
	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("(tenant_id IS NULL OR tenant_id = $%d)", argIdx))
		args = append(args, filter.TenantID.String())
		argIdx++
	} else {
		conditions = append(conditions, "tenant_id IS NULL")
	}

	// Filter by builtin status
	if filter.IsBuiltin != nil {
		conditions = append(conditions, fmt.Sprintf("is_builtin = $%d", argIdx))
		args = append(args, *filter.IsBuiltin)
		argIdx++
	}

	// Search by name or display name
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR display_name ILIKE $%d)", argIdx, argIdx))
		args = append(args, wrapLikePattern(filter.Search))
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := "SELECT COUNT(*) FROM tool_categories" + whereClause
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return pagination.Result[*toolcategory.ToolCategory]{}, fmt.Errorf("failed to count tool categories: %w", err)
	}

	// Fetch items
	query := r.selectQuery() + whereClause + " ORDER BY sort_order ASC, display_name ASC"
	query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, page.PerPage, page.Offset())

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*toolcategory.ToolCategory]{}, fmt.Errorf("failed to list tool categories: %w", err)
	}
	defer rows.Close()

	var categories []*toolcategory.ToolCategory
	for rows.Next() {
		tc, err := r.scanCategory(rows)
		if err != nil {
			return pagination.Result[*toolcategory.ToolCategory]{}, fmt.Errorf("failed to scan tool category: %w", err)
		}
		categories = append(categories, tc)
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*toolcategory.ToolCategory]{}, fmt.Errorf("failed to iterate tool categories: %w", err)
	}

	return pagination.NewResult(categories, total, page), nil
}

// ListAll returns all categories for a tenant context.
func (r *ToolCategoryRepository) ListAll(ctx context.Context, tenantID *shared.ID) ([]*toolcategory.ToolCategory, error) {
	var query string
	var args []any

	if tenantID != nil {
		// Include platform + tenant's own categories
		query = r.selectQuery() + " WHERE tenant_id IS NULL OR tenant_id = $1 ORDER BY sort_order ASC, display_name ASC"
		args = []any{tenantID.String()}
	} else {
		// Only platform categories
		query = r.selectQuery() + " WHERE tenant_id IS NULL ORDER BY sort_order ASC, display_name ASC"
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list all tool categories: %w", err)
	}
	defer rows.Close()

	var categories []*toolcategory.ToolCategory
	for rows.Next() {
		tc, err := r.scanCategory(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan tool category: %w", err)
		}
		categories = append(categories, tc)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate tool categories: %w", err)
	}

	return categories, nil
}

// Update updates an existing category.
func (r *ToolCategoryRepository) Update(ctx context.Context, tc *toolcategory.ToolCategory) error {
	query := `
		UPDATE tool_categories SET
			display_name = $2,
			description = $3,
			icon = $4,
			color = $5,
			sort_order = $6,
			updated_at = $7
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		tc.ID.String(),
		tc.DisplayName,
		tc.Description,
		tc.Icon,
		tc.Color,
		tc.SortOrder,
		tc.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to update tool category: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("%w: tool category not found", shared.ErrNotFound)
	}

	return nil
}

// Delete deletes a category by ID.
func (r *ToolCategoryRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM tool_categories WHERE id = $1 AND is_builtin = false"

	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete tool category: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("%w: tool category not found or is a builtin category", shared.ErrNotFound)
	}

	return nil
}

// ExistsByName checks if a category with the given name exists in the scope.
func (r *ToolCategoryRepository) ExistsByName(ctx context.Context, tenantID *shared.ID, name string) (bool, error) {
	var query string
	var args []any

	if tenantID == nil {
		query = "SELECT EXISTS(SELECT 1 FROM tool_categories WHERE tenant_id IS NULL AND name = $1)"
		args = []any{name}
	} else {
		query = "SELECT EXISTS(SELECT 1 FROM tool_categories WHERE tenant_id = $1 AND name = $2)"
		args = []any{tenantID.String(), name}
	}

	var exists bool
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check category existence: %w", err)
	}

	return exists, nil
}

// CountByTenant returns the number of custom categories for a tenant.
func (r *ToolCategoryRepository) CountByTenant(ctx context.Context, tenantID shared.ID) (int64, error) {
	query := "SELECT COUNT(*) FROM tool_categories WHERE tenant_id = $1"

	var count int64
	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count tenant categories: %w", err)
	}

	return count, nil
}
