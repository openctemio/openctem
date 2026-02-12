package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/api/pkg/domain/assettype"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// AssetTypeCategoryRepository implements assettype.CategoryRepository using PostgreSQL.
type AssetTypeCategoryRepository struct {
	db *DB
}

// NewAssetTypeCategoryRepository creates a new category repository.
func NewAssetTypeCategoryRepository(db *DB) *AssetTypeCategoryRepository {
	return &AssetTypeCategoryRepository{db: db}
}

const categorySelectQuery = `
	SELECT
		id, code, name, description, icon, display_order, is_active, created_at, updated_at
	FROM asset_type_categories
`

func (r *AssetTypeCategoryRepository) scanCategory(row interface{ Scan(...any) error }) (*assettype.Category, error) {
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
	return assettype.ReconstituteCategory(
		cid, code, name, description.String, icon.String,
		displayOrder, isActive, createdAt.Time, updatedAt.Time,
	), nil
}

// Create creates a new category.
func (r *AssetTypeCategoryRepository) Create(ctx context.Context, c *assettype.Category) error {
	query := `
		INSERT INTO asset_type_categories (
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
			return assettype.ErrCategoryCodeExists
		}
		return fmt.Errorf("create category: %w", err)
	}

	return nil
}

// GetByID retrieves a category by ID.
func (r *AssetTypeCategoryRepository) GetByID(ctx context.Context, id shared.ID) (*assettype.Category, error) {
	query := categorySelectQuery + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())

	c, err := r.scanCategory(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, assettype.ErrCategoryNotFound
		}
		return nil, fmt.Errorf("get category: %w", err)
	}

	return c, nil
}

// GetByCode retrieves a category by code.
func (r *AssetTypeCategoryRepository) GetByCode(ctx context.Context, code string) (*assettype.Category, error) {
	query := categorySelectQuery + " WHERE code = $1"
	row := r.db.QueryRowContext(ctx, query, code)

	c, err := r.scanCategory(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, assettype.ErrCategoryNotFound
		}
		return nil, fmt.Errorf("get category by code: %w", err)
	}

	return c, nil
}

// Update updates an existing category.
func (r *AssetTypeCategoryRepository) Update(ctx context.Context, c *assettype.Category) error {
	query := `
		UPDATE asset_type_categories SET
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
		return fmt.Errorf("update category: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return assettype.ErrCategoryNotFound
	}

	return nil
}

// Delete deletes a category.
func (r *AssetTypeCategoryRepository) Delete(ctx context.Context, id shared.ID) error {
	// Check if category has asset types
	var count int
	checkQuery := "SELECT COUNT(*) FROM asset_types WHERE category_id = $1"
	if err := r.db.QueryRowContext(ctx, checkQuery, id.String()).Scan(&count); err != nil {
		return fmt.Errorf("check category asset types: %w", err)
	}
	if count > 0 {
		return assettype.ErrCategoryHasAssetTypes
	}

	query := "DELETE FROM asset_type_categories WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("delete category: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return assettype.ErrCategoryNotFound
	}

	return nil
}

// List lists categories with pagination.
//
//nolint:dupl // Similar to FindingSourceCategoryRepository.List but different table and types
func (r *AssetTypeCategoryRepository) List(
	ctx context.Context,
	filter assettype.CategoryFilter,
	page pagination.Pagination,
) (pagination.Result[*assettype.Category], error) {
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
	countQuery := "SELECT COUNT(*) FROM asset_type_categories" + whereClause
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return pagination.Result[*assettype.Category]{}, fmt.Errorf("count categories: %w", err)
	}

	// Query with pagination
	query := categorySelectQuery + whereClause + " ORDER BY display_order, name" +
		fmt.Sprintf(" LIMIT $%d OFFSET $%d", argNum, argNum+1)
	args = append(args, page.Limit(), page.Offset())

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*assettype.Category]{}, fmt.Errorf("list categories: %w", err)
	}
	defer rows.Close()

	var categories []*assettype.Category
	for rows.Next() {
		c, err := r.scanCategory(rows)
		if err != nil {
			return pagination.Result[*assettype.Category]{}, fmt.Errorf("scan category: %w", err)
		}
		categories = append(categories, c)
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*assettype.Category]{}, fmt.Errorf("iterate categories: %w", err)
	}

	return pagination.NewResult(categories, total, page), nil
}

// ListActive lists all active categories.
func (r *AssetTypeCategoryRepository) ListActive(ctx context.Context) ([]*assettype.Category, error) {
	query := categorySelectQuery + " WHERE is_active = true ORDER BY display_order, name"

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list active categories: %w", err)
	}
	defer rows.Close()

	var categories []*assettype.Category
	for rows.Next() {
		c, err := r.scanCategory(rows)
		if err != nil {
			return nil, fmt.Errorf("scan category: %w", err)
		}
		categories = append(categories, c)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active categories: %w", err)
	}

	return categories, nil
}

// AssetTypeRepository implements assettype.Repository using PostgreSQL.
type AssetTypeRepository struct {
	db *DB
}

// NewAssetTypeRepository creates a new asset type repository.
func NewAssetTypeRepository(db *DB) *AssetTypeRepository {
	return &AssetTypeRepository{db: db}
}

const assetTypeSelectQuery = `
	SELECT
		at.id, at.category_id, at.code, at.name, at.description,
		at.icon, at.color, at.display_order,
		at.pattern_regex, at.pattern_placeholder, at.pattern_example,
		at.supports_wildcard, at.supports_cidr, at.is_discoverable, at.is_scannable,
		at.is_system, at.is_active, at.created_at, at.updated_at
	FROM asset_types at
`

func (r *AssetTypeRepository) scanAssetType(row interface{ Scan(...any) error }) (*assettype.AssetType, error) {
	var (
		id                 string
		categoryID         sql.NullString
		code               string
		name               string
		description        sql.NullString
		icon               sql.NullString
		color              sql.NullString
		displayOrder       int
		patternRegex       sql.NullString
		patternPlaceholder sql.NullString
		patternExample     sql.NullString
		supportsWildcard   bool
		supportsCIDR       bool
		isDiscoverable     bool
		isScannable        bool
		isSystem           bool
		isActive           bool
		createdAt          sql.NullTime
		updatedAt          sql.NullTime
	)

	err := row.Scan(
		&id, &categoryID, &code, &name, &description,
		&icon, &color, &displayOrder,
		&patternRegex, &patternPlaceholder, &patternExample,
		&supportsWildcard, &supportsCIDR, &isDiscoverable, &isScannable,
		&isSystem, &isActive, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	atID, _ := shared.IDFromString(id)

	var categoryIDPtr *shared.ID
	if categoryID.Valid {
		cid, _ := shared.IDFromString(categoryID.String)
		categoryIDPtr = &cid
	}

	return assettype.ReconstituteAssetType(
		atID, categoryIDPtr,
		code, name, description.String,
		icon.String, color.String, displayOrder,
		patternRegex.String, patternPlaceholder.String, patternExample.String,
		supportsWildcard, supportsCIDR, isDiscoverable, isScannable,
		isSystem, isActive, createdAt.Time, updatedAt.Time,
	), nil
}

// GetByID retrieves an asset type by ID.
func (r *AssetTypeRepository) GetByID(ctx context.Context, id shared.ID) (*assettype.AssetType, error) {
	query := assetTypeSelectQuery + " WHERE at.id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())

	at, err := r.scanAssetType(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, assettype.ErrAssetTypeNotFound
		}
		return nil, fmt.Errorf("get asset type: %w", err)
	}

	return at, nil
}

// GetByCode retrieves an asset type by its code.
func (r *AssetTypeRepository) GetByCode(ctx context.Context, code string) (*assettype.AssetType, error) {
	query := assetTypeSelectQuery + " WHERE at.code = $1"
	row := r.db.QueryRowContext(ctx, query, code)

	at, err := r.scanAssetType(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, assettype.ErrAssetTypeNotFound
		}
		return nil, fmt.Errorf("get asset type by code: %w", err)
	}

	return at, nil
}

// List lists asset types with filtering and pagination.
//
//nolint:dupl // Similar to FindingSourceRepository.List but different table and types
func (r *AssetTypeRepository) List(
	ctx context.Context,
	filter assettype.Filter,
	opts assettype.ListOptions,
	page pagination.Pagination,
) (pagination.Result[*assettype.AssetType], error) {
	conditions, args, argNum := r.buildFilterConditions(filter)

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := "SELECT COUNT(*) FROM asset_types at" + whereClause
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return pagination.Result[*assettype.AssetType]{}, fmt.Errorf("count asset types: %w", err)
	}

	// Build order clause
	orderClause := " ORDER BY at.display_order, at.name"
	if opts.Sort != nil && !opts.Sort.IsEmpty() {
		orderClause = " ORDER BY at." + opts.Sort.SQL()
	}

	// Query with pagination
	query := assetTypeSelectQuery + whereClause + orderClause +
		fmt.Sprintf(" LIMIT $%d OFFSET $%d", argNum, argNum+1)
	args = append(args, page.Limit(), page.Offset())

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*assettype.AssetType]{}, fmt.Errorf("list asset types: %w", err)
	}
	defer rows.Close()

	var assetTypes []*assettype.AssetType
	for rows.Next() {
		at, err := r.scanAssetType(rows)
		if err != nil {
			return pagination.Result[*assettype.AssetType]{}, fmt.Errorf("scan asset type: %w", err)
		}
		assetTypes = append(assetTypes, at)
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*assettype.AssetType]{}, fmt.Errorf("iterate asset types: %w", err)
	}

	return pagination.NewResult(assetTypes, total, page), nil
}

// ListWithCategory lists asset types with their categories.
func (r *AssetTypeRepository) ListWithCategory(
	ctx context.Context,
	filter assettype.Filter,
	opts assettype.ListOptions,
	page pagination.Pagination,
) (pagination.Result[*assettype.AssetTypeWithCategory], error) {
	conditions, args, argNum := r.buildFilterConditions(filter)

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := "SELECT COUNT(*) FROM asset_types at" + whereClause
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return pagination.Result[*assettype.AssetTypeWithCategory]{}, fmt.Errorf("count asset types: %w", err)
	}

	// Build order clause
	orderClause := " ORDER BY at.display_order, at.name"
	if opts.Sort != nil && !opts.Sort.IsEmpty() {
		orderClause = " ORDER BY at." + opts.Sort.SQL()
	}

	// Query with category join
	query := `
		SELECT
			at.id, at.category_id, at.code, at.name, at.description,
			at.icon, at.color, at.display_order,
			at.pattern_regex, at.pattern_placeholder, at.pattern_example,
			at.supports_wildcard, at.supports_cidr, at.is_discoverable, at.is_scannable,
			at.is_system, at.is_active, at.created_at, at.updated_at,
			c.id, c.code, c.name, c.description, c.icon, c.display_order, c.is_active, c.created_at, c.updated_at
		FROM asset_types at
		LEFT JOIN asset_type_categories c ON at.category_id = c.id
	` + whereClause + orderClause + fmt.Sprintf(" LIMIT $%d OFFSET $%d", argNum, argNum+1)
	args = append(args, page.Limit(), page.Offset())

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*assettype.AssetTypeWithCategory]{}, fmt.Errorf("list asset types with category: %w", err)
	}
	defer rows.Close()

	var results []*assettype.AssetTypeWithCategory
	for rows.Next() {
		var (
			// Asset type fields
			atID               string
			atCategoryID       sql.NullString
			atCode             string
			atName             string
			atDescription      sql.NullString
			atIcon             sql.NullString
			atColor            sql.NullString
			atDisplayOrder     int
			atPatternRegex     sql.NullString
			atPatternPlacehold sql.NullString
			atPatternExample   sql.NullString
			atSupportsWildcard bool
			atSupportsCIDR     bool
			atIsDiscoverable   bool
			atIsScannable      bool
			atIsSystem         bool
			atIsActive         bool
			atCreatedAt        sql.NullTime
			atUpdatedAt        sql.NullTime
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
			&atID, &atCategoryID, &atCode, &atName, &atDescription,
			&atIcon, &atColor, &atDisplayOrder,
			&atPatternRegex, &atPatternPlacehold, &atPatternExample,
			&atSupportsWildcard, &atSupportsCIDR, &atIsDiscoverable, &atIsScannable,
			&atIsSystem, &atIsActive, &atCreatedAt, &atUpdatedAt,
			&cID, &cCode, &cName, &cDescription, &cIcon, &cDisplayOrder, &cIsActive, &cCreatedAt, &cUpdatedAt,
		)
		if err != nil {
			return pagination.Result[*assettype.AssetTypeWithCategory]{}, fmt.Errorf("scan asset type with category: %w", err)
		}

		// Reconstruct asset type
		atIDParsed, _ := shared.IDFromString(atID)
		var categoryIDPtr *shared.ID
		if atCategoryID.Valid {
			cid, _ := shared.IDFromString(atCategoryID.String)
			categoryIDPtr = &cid
		}

		at := assettype.ReconstituteAssetType(
			atIDParsed, categoryIDPtr,
			atCode, atName, atDescription.String,
			atIcon.String, atColor.String, atDisplayOrder,
			atPatternRegex.String, atPatternPlacehold.String, atPatternExample.String,
			atSupportsWildcard, atSupportsCIDR, atIsDiscoverable, atIsScannable,
			atIsSystem, atIsActive, atCreatedAt.Time, atUpdatedAt.Time,
		)

		// Reconstruct category if present
		var category *assettype.Category
		if cID.Valid {
			cidParsed, _ := shared.IDFromString(cID.String)
			category = assettype.ReconstituteCategory(
				cidParsed, cCode.String, cName.String, cDescription.String, cIcon.String,
				int(cDisplayOrder.Int64), cIsActive.Bool, cCreatedAt.Time, cUpdatedAt.Time,
			)
		}

		results = append(results, &assettype.AssetTypeWithCategory{
			AssetType: at,
			Category:  category,
		})
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*assettype.AssetTypeWithCategory]{}, fmt.Errorf("iterate asset types with category: %w", err)
	}

	return pagination.NewResult(results, total, page), nil
}

// ListActive lists all active asset types.
func (r *AssetTypeRepository) ListActive(ctx context.Context) ([]*assettype.AssetType, error) {
	query := assetTypeSelectQuery + " WHERE at.is_active = true ORDER BY at.display_order, at.name"

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list active asset types: %w", err)
	}
	defer rows.Close()

	var assetTypes []*assettype.AssetType
	for rows.Next() {
		at, err := r.scanAssetType(rows)
		if err != nil {
			return nil, fmt.Errorf("scan asset type: %w", err)
		}
		assetTypes = append(assetTypes, at)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active asset types: %w", err)
	}

	return assetTypes, nil
}

// ListActiveByCategory lists active asset types by category.
func (r *AssetTypeRepository) ListActiveByCategory(ctx context.Context, categoryID shared.ID) ([]*assettype.AssetType, error) {
	query := assetTypeSelectQuery + " WHERE at.is_active = true AND at.category_id = $1 ORDER BY at.display_order, at.name"

	rows, err := r.db.QueryContext(ctx, query, categoryID.String())
	if err != nil {
		return nil, fmt.Errorf("list active asset types by category: %w", err)
	}
	defer rows.Close()

	var assetTypes []*assettype.AssetType
	for rows.Next() {
		at, err := r.scanAssetType(rows)
		if err != nil {
			return nil, fmt.Errorf("scan asset type: %w", err)
		}
		assetTypes = append(assetTypes, at)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate asset types by category: %w", err)
	}

	return assetTypes, nil
}

// ExistsByCode checks if an asset type with the given code exists.
func (r *AssetTypeRepository) ExistsByCode(ctx context.Context, code string) (bool, error) {
	query := "SELECT EXISTS(SELECT 1 FROM asset_types WHERE code = $1)"

	var exists bool
	if err := r.db.QueryRowContext(ctx, query, code).Scan(&exists); err != nil {
		return false, fmt.Errorf("exists by code: %w", err)
	}
	return exists, nil
}

// buildFilterConditions builds filter conditions for queries.
func (r *AssetTypeRepository) buildFilterConditions(filter assettype.Filter) ([]string, []any, int) {
	var conditions []string
	var args []any
	argNum := 1

	if filter.CategoryID != nil && *filter.CategoryID != "" {
		conditions = append(conditions, fmt.Sprintf("at.category_id = $%d", argNum))
		args = append(args, *filter.CategoryID)
		argNum++
	}

	if filter.Code != nil && *filter.Code != "" {
		conditions = append(conditions, fmt.Sprintf("at.code = $%d", argNum))
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
		conditions = append(conditions, fmt.Sprintf("at.code IN (%s)", strings.Join(placeholders, ", ")))
	}

	if filter.Name != nil && *filter.Name != "" {
		conditions = append(conditions, fmt.Sprintf("at.name ILIKE $%d", argNum))
		args = append(args, wrapLikePattern(*filter.Name))
		argNum++
	}

	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("at.is_active = $%d", argNum))
		args = append(args, *filter.IsActive)
		argNum++
	}

	if filter.IsSystem != nil {
		conditions = append(conditions, fmt.Sprintf("at.is_system = $%d", argNum))
		args = append(args, *filter.IsSystem)
		argNum++
	}

	if filter.IsDiscoverable != nil {
		conditions = append(conditions, fmt.Sprintf("at.is_discoverable = $%d", argNum))
		args = append(args, *filter.IsDiscoverable)
		argNum++
	}

	if filter.IsScannable != nil {
		conditions = append(conditions, fmt.Sprintf("at.is_scannable = $%d", argNum))
		args = append(args, *filter.IsScannable)
		argNum++
	}

	if filter.SupportsWildcard != nil {
		conditions = append(conditions, fmt.Sprintf("at.supports_wildcard = $%d", argNum))
		args = append(args, *filter.SupportsWildcard)
		argNum++
	}

	if filter.SupportsCIDR != nil {
		conditions = append(conditions, fmt.Sprintf("at.supports_cidr = $%d", argNum))
		args = append(args, *filter.SupportsCIDR)
		argNum++
	}

	if filter.Search != nil && *filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(at.name ILIKE $%d OR at.description ILIKE $%d OR at.code ILIKE $%d)", argNum, argNum, argNum))
		args = append(args, wrapLikePattern(*filter.Search))
		argNum++
	}

	return conditions, args, argNum
}
