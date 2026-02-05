package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/api/pkg/domain/findingsource"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// FindingSourceCategoryRepository implements findingsource.CategoryRepository using PostgreSQL.
type FindingSourceCategoryRepository struct {
	db *DB
}

// NewFindingSourceCategoryRepository creates a new category repository.
func NewFindingSourceCategoryRepository(db *DB) *FindingSourceCategoryRepository {
	return &FindingSourceCategoryRepository{db: db}
}

const findingSourceCategorySelectQuery = `
	SELECT
		id, code, name, description, icon, display_order, is_active, created_at, updated_at
	FROM finding_source_categories
`

func (r *FindingSourceCategoryRepository) scanCategory(row interface{ Scan(...any) error }) (*findingsource.Category, error) {
	var (
		id           string
		code         string
		name         string
		description  sql.NullString
		icon         sql.NullString
		displayOrder int
		isActive     bool
		createdAt    sql.NullTime
		updatedAt    sql.NullTime
	)

	err := row.Scan(&id, &code, &name, &description, &icon, &displayOrder, &isActive, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}

	cid, _ := shared.IDFromString(id)
	return findingsource.ReconstituteCategory(
		cid, code, name, description.String, icon.String,
		displayOrder, isActive, createdAt.Time, updatedAt.Time,
	), nil
}

// Create creates a new category.
func (r *FindingSourceCategoryRepository) Create(ctx context.Context, c *findingsource.Category) error {
	query := `
		INSERT INTO finding_source_categories (
			id, code, name, description, icon, display_order, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	_, err := r.db.ExecContext(ctx, query,
		c.ID().String(),
		c.Code(),
		c.Name(),
		nullString(c.Description()),
		nullString(c.Icon()),
		c.DisplayOrder(),
		c.IsActive(),
		c.CreatedAt(),
		c.UpdatedAt(),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return findingsource.ErrCategoryCodeExists
		}
		return fmt.Errorf("create finding source category: %w", err)
	}

	return nil
}

// GetByID retrieves a category by ID.
func (r *FindingSourceCategoryRepository) GetByID(ctx context.Context, id shared.ID) (*findingsource.Category, error) {
	query := findingSourceCategorySelectQuery + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())

	c, err := r.scanCategory(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, findingsource.ErrCategoryNotFound
		}
		return nil, fmt.Errorf("get finding source category: %w", err)
	}

	return c, nil
}

// GetByCode retrieves a category by code.
func (r *FindingSourceCategoryRepository) GetByCode(ctx context.Context, code string) (*findingsource.Category, error) {
	query := findingSourceCategorySelectQuery + " WHERE code = $1"
	row := r.db.QueryRowContext(ctx, query, code)

	c, err := r.scanCategory(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, findingsource.ErrCategoryNotFound
		}
		return nil, fmt.Errorf("get finding source category by code: %w", err)
	}

	return c, nil
}

// Update updates an existing category.
func (r *FindingSourceCategoryRepository) Update(ctx context.Context, c *findingsource.Category) error {
	query := `
		UPDATE finding_source_categories SET
			name = $2,
			description = $3,
			icon = $4,
			display_order = $5,
			is_active = $6,
			updated_at = $7
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		c.ID().String(),
		c.Name(),
		nullString(c.Description()),
		nullString(c.Icon()),
		c.DisplayOrder(),
		c.IsActive(),
		c.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("update finding source category: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return findingsource.ErrCategoryNotFound
	}

	return nil
}

// Delete deletes a category.
func (r *FindingSourceCategoryRepository) Delete(ctx context.Context, id shared.ID) error {
	// Check if category has finding sources
	var count int
	checkQuery := "SELECT COUNT(*) FROM finding_sources WHERE category_id = $1"
	if err := r.db.QueryRowContext(ctx, checkQuery, id.String()).Scan(&count); err != nil {
		return fmt.Errorf("check category finding sources: %w", err)
	}
	if count > 0 {
		return findingsource.ErrCategoryHasFindingSources
	}

	query := "DELETE FROM finding_source_categories WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("delete finding source category: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return findingsource.ErrCategoryNotFound
	}

	return nil
}

// List lists categories with pagination.
func (r *FindingSourceCategoryRepository) List(
	ctx context.Context,
	filter findingsource.CategoryFilter,
	page pagination.Pagination,
) (pagination.Result[*findingsource.Category], error) {
	var conditions []string
	var args []any
	argNum := 1

	if filter.Code != nil && *filter.Code != "" {
		conditions = append(conditions, fmt.Sprintf("code = $%d", argNum))
		args = append(args, *filter.Code)
		argNum++
	}

	if filter.Name != nil && *filter.Name != "" {
		conditions = append(conditions, fmt.Sprintf("name ILIKE $%d", argNum))
		args = append(args, wrapLikePattern(*filter.Name))
		argNum++
	}

	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argNum))
		args = append(args, *filter.IsActive)
		argNum++
	}

	if filter.Search != nil && *filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argNum, argNum))
		args = append(args, wrapLikePattern(*filter.Search))
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := "SELECT COUNT(*) FROM finding_source_categories" + whereClause
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return pagination.Result[*findingsource.Category]{}, fmt.Errorf("count finding source categories: %w", err)
	}

	// Query with pagination
	query := findingSourceCategorySelectQuery + whereClause + " ORDER BY display_order, name" +
		fmt.Sprintf(" LIMIT $%d OFFSET $%d", argNum, argNum+1)
	args = append(args, page.Limit(), page.Offset())

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*findingsource.Category]{}, fmt.Errorf("list finding source categories: %w", err)
	}
	defer rows.Close()

	var categories []*findingsource.Category
	for rows.Next() {
		c, err := r.scanCategory(rows)
		if err != nil {
			return pagination.Result[*findingsource.Category]{}, fmt.Errorf("scan finding source category: %w", err)
		}
		categories = append(categories, c)
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*findingsource.Category]{}, fmt.Errorf("iterate finding source categories: %w", err)
	}

	return pagination.NewResult(categories, total, page), nil
}

// ListActive lists all active categories.
func (r *FindingSourceCategoryRepository) ListActive(ctx context.Context) ([]*findingsource.Category, error) {
	query := findingSourceCategorySelectQuery + " WHERE is_active = true ORDER BY display_order, name"

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list active finding source categories: %w", err)
	}
	defer rows.Close()

	var categories []*findingsource.Category
	for rows.Next() {
		c, err := r.scanCategory(rows)
		if err != nil {
			return nil, fmt.Errorf("scan finding source category: %w", err)
		}
		categories = append(categories, c)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active finding source categories: %w", err)
	}

	return categories, nil
}

// FindingSourceRepository implements findingsource.Repository using PostgreSQL.
type FindingSourceRepository struct {
	db *DB
}

// NewFindingSourceRepository creates a new finding source repository.
func NewFindingSourceRepository(db *DB) *FindingSourceRepository {
	return &FindingSourceRepository{db: db}
}

const findingSourceSelectQuery = `
	SELECT
		fs.id, fs.category_id, fs.code, fs.name, fs.description,
		fs.icon, fs.color, fs.display_order,
		fs.is_system, fs.is_active, fs.created_at, fs.updated_at
	FROM finding_sources fs
`

func (r *FindingSourceRepository) scanFindingSource(row interface{ Scan(...any) error }) (*findingsource.FindingSource, error) {
	var (
		id           string
		categoryID   sql.NullString
		code         string
		name         string
		description  sql.NullString
		icon         sql.NullString
		color        sql.NullString
		displayOrder int
		isSystem     bool
		isActive     bool
		createdAt    sql.NullTime
		updatedAt    sql.NullTime
	)

	err := row.Scan(
		&id, &categoryID, &code, &name, &description,
		&icon, &color, &displayOrder,
		&isSystem, &isActive, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	fsID, _ := shared.IDFromString(id)

	var categoryIDPtr *shared.ID
	if categoryID.Valid {
		cid, _ := shared.IDFromString(categoryID.String)
		categoryIDPtr = &cid
	}

	return findingsource.ReconstituteFindingSource(
		fsID, categoryIDPtr,
		code, name, description.String,
		icon.String, color.String, displayOrder,
		isSystem, isActive, createdAt.Time, updatedAt.Time,
	), nil
}

// GetByID retrieves a finding source by ID.
func (r *FindingSourceRepository) GetByID(ctx context.Context, id shared.ID) (*findingsource.FindingSource, error) {
	query := findingSourceSelectQuery + " WHERE fs.id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())

	fs, err := r.scanFindingSource(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, findingsource.ErrFindingSourceNotFound
		}
		return nil, fmt.Errorf("get finding source: %w", err)
	}

	return fs, nil
}

// GetByCode retrieves a finding source by its code.
func (r *FindingSourceRepository) GetByCode(ctx context.Context, code string) (*findingsource.FindingSource, error) {
	query := findingSourceSelectQuery + " WHERE fs.code = $1"
	row := r.db.QueryRowContext(ctx, query, code)

	fs, err := r.scanFindingSource(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, findingsource.ErrFindingSourceNotFound
		}
		return nil, fmt.Errorf("get finding source by code: %w", err)
	}

	return fs, nil
}

// List lists finding sources with filtering and pagination.
func (r *FindingSourceRepository) List(
	ctx context.Context,
	filter findingsource.Filter,
	opts findingsource.ListOptions,
	page pagination.Pagination,
) (pagination.Result[*findingsource.FindingSource], error) {
	conditions, args, argNum := r.buildFilterConditions(filter)

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := "SELECT COUNT(*) FROM finding_sources fs" + whereClause
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return pagination.Result[*findingsource.FindingSource]{}, fmt.Errorf("count finding sources: %w", err)
	}

	// Build order clause
	orderClause := " ORDER BY fs.display_order, fs.name"
	if opts.Sort != nil && !opts.Sort.IsEmpty() {
		orderClause = " ORDER BY fs." + opts.Sort.SQL()
	}

	// Query with pagination
	query := findingSourceSelectQuery + whereClause + orderClause +
		fmt.Sprintf(" LIMIT $%d OFFSET $%d", argNum, argNum+1)
	args = append(args, page.Limit(), page.Offset())

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*findingsource.FindingSource]{}, fmt.Errorf("list finding sources: %w", err)
	}
	defer rows.Close()

	var findingSources []*findingsource.FindingSource
	for rows.Next() {
		fs, err := r.scanFindingSource(rows)
		if err != nil {
			return pagination.Result[*findingsource.FindingSource]{}, fmt.Errorf("scan finding source: %w", err)
		}
		findingSources = append(findingSources, fs)
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*findingsource.FindingSource]{}, fmt.Errorf("iterate finding sources: %w", err)
	}

	return pagination.NewResult(findingSources, total, page), nil
}

// ListWithCategory lists finding sources with their categories.
func (r *FindingSourceRepository) ListWithCategory(
	ctx context.Context,
	filter findingsource.Filter,
	opts findingsource.ListOptions,
	page pagination.Pagination,
) (pagination.Result[*findingsource.FindingSourceWithCategory], error) {
	conditions, args, argNum := r.buildFilterConditions(filter)

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := "SELECT COUNT(*) FROM finding_sources fs" + whereClause
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return pagination.Result[*findingsource.FindingSourceWithCategory]{}, fmt.Errorf("count finding sources: %w", err)
	}

	// Build order clause
	orderClause := " ORDER BY fs.display_order, fs.name"
	if opts.Sort != nil && !opts.Sort.IsEmpty() {
		orderClause = " ORDER BY fs." + opts.Sort.SQL()
	}

	// Query with category join
	query := `
		SELECT
			fs.id, fs.category_id, fs.code, fs.name, fs.description,
			fs.icon, fs.color, fs.display_order,
			fs.is_system, fs.is_active, fs.created_at, fs.updated_at,
			c.id, c.code, c.name, c.description, c.icon, c.display_order, c.is_active, c.created_at, c.updated_at
		FROM finding_sources fs
		LEFT JOIN finding_source_categories c ON fs.category_id = c.id
	` + whereClause + orderClause + fmt.Sprintf(" LIMIT $%d OFFSET $%d", argNum, argNum+1)
	args = append(args, page.Limit(), page.Offset())

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*findingsource.FindingSourceWithCategory]{}, fmt.Errorf("list finding sources with category: %w", err)
	}
	defer rows.Close()

	var results []*findingsource.FindingSourceWithCategory
	for rows.Next() {
		var (
			// Finding source fields
			fsID           string
			fsCategoryID   sql.NullString
			fsCode         string
			fsName         string
			fsDescription  sql.NullString
			fsIcon         sql.NullString
			fsColor        sql.NullString
			fsDisplayOrder int
			fsIsSystem     bool
			fsIsActive     bool
			fsCreatedAt    sql.NullTime
			fsUpdatedAt    sql.NullTime
			// Category fields (nullable due to LEFT JOIN)
			cID           sql.NullString
			cCode         sql.NullString
			cName         sql.NullString
			cDescription  sql.NullString
			cIcon         sql.NullString
			cDisplayOrder sql.NullInt64
			cIsActive     sql.NullBool
			cCreatedAt    sql.NullTime
			cUpdatedAt    sql.NullTime
		)

		err := rows.Scan(
			&fsID, &fsCategoryID, &fsCode, &fsName, &fsDescription,
			&fsIcon, &fsColor, &fsDisplayOrder,
			&fsIsSystem, &fsIsActive, &fsCreatedAt, &fsUpdatedAt,
			&cID, &cCode, &cName, &cDescription, &cIcon, &cDisplayOrder, &cIsActive, &cCreatedAt, &cUpdatedAt,
		)
		if err != nil {
			return pagination.Result[*findingsource.FindingSourceWithCategory]{}, fmt.Errorf("scan finding source with category: %w", err)
		}

		// Reconstruct finding source
		fsIDParsed, _ := shared.IDFromString(fsID)
		var categoryIDPtr *shared.ID
		if fsCategoryID.Valid {
			cid, _ := shared.IDFromString(fsCategoryID.String)
			categoryIDPtr = &cid
		}

		fs := findingsource.ReconstituteFindingSource(
			fsIDParsed, categoryIDPtr,
			fsCode, fsName, fsDescription.String,
			fsIcon.String, fsColor.String, fsDisplayOrder,
			fsIsSystem, fsIsActive, fsCreatedAt.Time, fsUpdatedAt.Time,
		)

		// Reconstruct category if present
		var category *findingsource.Category
		if cID.Valid {
			cidParsed, _ := shared.IDFromString(cID.String)
			category = findingsource.ReconstituteCategory(
				cidParsed, cCode.String, cName.String, cDescription.String, cIcon.String,
				int(cDisplayOrder.Int64), cIsActive.Bool, cCreatedAt.Time, cUpdatedAt.Time,
			)
		}

		results = append(results, &findingsource.FindingSourceWithCategory{
			FindingSource: fs,
			Category:      category,
		})
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*findingsource.FindingSourceWithCategory]{}, fmt.Errorf("iterate finding sources with category: %w", err)
	}

	return pagination.NewResult(results, total, page), nil
}

// ListActive lists all active finding sources.
func (r *FindingSourceRepository) ListActive(ctx context.Context) ([]*findingsource.FindingSource, error) {
	query := findingSourceSelectQuery + " WHERE fs.is_active = true ORDER BY fs.display_order, fs.name"

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list active finding sources: %w", err)
	}
	defer rows.Close()

	var findingSources []*findingsource.FindingSource
	for rows.Next() {
		fs, err := r.scanFindingSource(rows)
		if err != nil {
			return nil, fmt.Errorf("scan finding source: %w", err)
		}
		findingSources = append(findingSources, fs)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active finding sources: %w", err)
	}

	return findingSources, nil
}

// ListActiveWithCategory lists all active finding sources with their categories.
func (r *FindingSourceRepository) ListActiveWithCategory(ctx context.Context) ([]*findingsource.FindingSourceWithCategory, error) {
	query := `
		SELECT
			fs.id, fs.category_id, fs.code, fs.name, fs.description,
			fs.icon, fs.color, fs.display_order,
			fs.is_system, fs.is_active, fs.created_at, fs.updated_at,
			c.id, c.code, c.name, c.description, c.icon, c.display_order, c.is_active, c.created_at, c.updated_at
		FROM finding_sources fs
		LEFT JOIN finding_source_categories c ON fs.category_id = c.id
		WHERE fs.is_active = true
		ORDER BY c.display_order, fs.display_order, fs.name
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list active finding sources with category: %w", err)
	}
	defer rows.Close()

	var results []*findingsource.FindingSourceWithCategory
	for rows.Next() {
		var (
			fsID           string
			fsCategoryID   sql.NullString
			fsCode         string
			fsName         string
			fsDescription  sql.NullString
			fsIcon         sql.NullString
			fsColor        sql.NullString
			fsDisplayOrder int
			fsIsSystem     bool
			fsIsActive     bool
			fsCreatedAt    sql.NullTime
			fsUpdatedAt    sql.NullTime
			cID            sql.NullString
			cCode          sql.NullString
			cName          sql.NullString
			cDescription   sql.NullString
			cIcon          sql.NullString
			cDisplayOrder  sql.NullInt64
			cIsActive      sql.NullBool
			cCreatedAt     sql.NullTime
			cUpdatedAt     sql.NullTime
		)

		err := rows.Scan(
			&fsID, &fsCategoryID, &fsCode, &fsName, &fsDescription,
			&fsIcon, &fsColor, &fsDisplayOrder,
			&fsIsSystem, &fsIsActive, &fsCreatedAt, &fsUpdatedAt,
			&cID, &cCode, &cName, &cDescription, &cIcon, &cDisplayOrder, &cIsActive, &cCreatedAt, &cUpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan finding source with category: %w", err)
		}

		fsIDParsed, _ := shared.IDFromString(fsID)
		var categoryIDPtr *shared.ID
		if fsCategoryID.Valid {
			cid, _ := shared.IDFromString(fsCategoryID.String)
			categoryIDPtr = &cid
		}

		fs := findingsource.ReconstituteFindingSource(
			fsIDParsed, categoryIDPtr,
			fsCode, fsName, fsDescription.String,
			fsIcon.String, fsColor.String, fsDisplayOrder,
			fsIsSystem, fsIsActive, fsCreatedAt.Time, fsUpdatedAt.Time,
		)

		var category *findingsource.Category
		if cID.Valid {
			cidParsed, _ := shared.IDFromString(cID.String)
			category = findingsource.ReconstituteCategory(
				cidParsed, cCode.String, cName.String, cDescription.String, cIcon.String,
				int(cDisplayOrder.Int64), cIsActive.Bool, cCreatedAt.Time, cUpdatedAt.Time,
			)
		}

		results = append(results, &findingsource.FindingSourceWithCategory{
			FindingSource: fs,
			Category:      category,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active finding sources with category: %w", err)
	}

	return results, nil
}

// ListActiveByCategory lists active finding sources by category.
func (r *FindingSourceRepository) ListActiveByCategory(ctx context.Context, categoryID shared.ID) ([]*findingsource.FindingSource, error) {
	query := findingSourceSelectQuery + " WHERE fs.is_active = true AND fs.category_id = $1 ORDER BY fs.display_order, fs.name"

	rows, err := r.db.QueryContext(ctx, query, categoryID.String())
	if err != nil {
		return nil, fmt.Errorf("list active finding sources by category: %w", err)
	}
	defer rows.Close()

	var findingSources []*findingsource.FindingSource
	for rows.Next() {
		fs, err := r.scanFindingSource(rows)
		if err != nil {
			return nil, fmt.Errorf("scan finding source: %w", err)
		}
		findingSources = append(findingSources, fs)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate finding sources by category: %w", err)
	}

	return findingSources, nil
}

// ExistsByCode checks if a finding source with the given code exists.
func (r *FindingSourceRepository) ExistsByCode(ctx context.Context, code string) (bool, error) {
	query := "SELECT EXISTS(SELECT 1 FROM finding_sources WHERE code = $1)"

	var exists bool
	if err := r.db.QueryRowContext(ctx, query, code).Scan(&exists); err != nil {
		return false, fmt.Errorf("exists by code: %w", err)
	}
	return exists, nil
}

// IsValidCode checks if the code is a valid active finding source.
func (r *FindingSourceRepository) IsValidCode(ctx context.Context, code string) (bool, error) {
	query := "SELECT EXISTS(SELECT 1 FROM finding_sources WHERE code = $1 AND is_active = true)"

	var exists bool
	if err := r.db.QueryRowContext(ctx, query, code).Scan(&exists); err != nil {
		return false, fmt.Errorf("is valid code: %w", err)
	}
	return exists, nil
}

// buildFilterConditions builds filter conditions for queries.
func (r *FindingSourceRepository) buildFilterConditions(filter findingsource.Filter) ([]string, []any, int) {
	var conditions []string
	var args []any
	argNum := 1

	if filter.CategoryID != nil && *filter.CategoryID != "" {
		conditions = append(conditions, fmt.Sprintf("fs.category_id = $%d", argNum))
		args = append(args, *filter.CategoryID)
		argNum++
	}

	if filter.CategoryCode != nil && *filter.CategoryCode != "" {
		conditions = append(conditions, fmt.Sprintf("fs.category_id = (SELECT id FROM finding_source_categories WHERE code = $%d)", argNum))
		args = append(args, *filter.CategoryCode)
		argNum++
	}

	if filter.Code != nil && *filter.Code != "" {
		conditions = append(conditions, fmt.Sprintf("fs.code = $%d", argNum))
		args = append(args, *filter.Code)
		argNum++
	}

	if len(filter.Codes) > 0 {
		placeholders := make([]string, len(filter.Codes))
		for i, code := range filter.Codes {
			placeholders[i] = fmt.Sprintf("$%d", argNum)
			args = append(args, code)
			argNum++
		}
		conditions = append(conditions, fmt.Sprintf("fs.code IN (%s)", strings.Join(placeholders, ", ")))
	}

	if filter.Name != nil && *filter.Name != "" {
		conditions = append(conditions, fmt.Sprintf("fs.name ILIKE $%d", argNum))
		args = append(args, wrapLikePattern(*filter.Name))
		argNum++
	}

	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("fs.is_active = $%d", argNum))
		args = append(args, *filter.IsActive)
		argNum++
	}

	if filter.IsSystem != nil {
		conditions = append(conditions, fmt.Sprintf("fs.is_system = $%d", argNum))
		args = append(args, *filter.IsSystem)
		argNum++
	}

	if filter.Search != nil && *filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(fs.name ILIKE $%d OR fs.description ILIKE $%d OR fs.code ILIKE $%d)", argNum, argNum, argNum))
		args = append(args, wrapLikePattern(*filter.Search))
		argNum++
	}

	return conditions, args, argNum
}
