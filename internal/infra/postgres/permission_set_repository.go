package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/permissionset"
	"github.com/openctemio/api/pkg/domain/shared"
)

// PermissionSetRepository implements permissionset.Repository using PostgreSQL.
type PermissionSetRepository struct {
	db *DB
}

// NewPermissionSetRepository creates a new PermissionSetRepository.
func NewPermissionSetRepository(db *DB) *PermissionSetRepository {
	return &PermissionSetRepository{db: db}
}

// =============================================================================
// Permission Set CRUD Operations
// =============================================================================

// Create persists a new permission set.
func (r *PermissionSetRepository) Create(ctx context.Context, ps *permissionset.PermissionSet) error {
	query := `
		INSERT INTO permission_sets (
			id, tenant_id, name, slug, description, set_type,
			parent_set_id, cloned_from_version, is_active, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	var tenantID, parentSetID sql.NullString
	if ps.TenantID() != nil {
		tenantID = sql.NullString{String: ps.TenantID().String(), Valid: true}
	}
	if ps.ParentSetID() != nil {
		parentSetID = sql.NullString{String: ps.ParentSetID().String(), Valid: true}
	}

	var clonedFromVersion sql.NullInt32
	if ps.ClonedFromVersion() != nil {
		v := *ps.ClonedFromVersion()
		if v > math.MaxInt32 || v < math.MinInt32 {
			return fmt.Errorf("cloned_from_version value %d overflows int32", v)
		}
		clonedFromVersion = sql.NullInt32{Int32: int32(v), Valid: true} //nolint:gosec // bounds checked above
	}

	_, err := r.db.ExecContext(ctx, query,
		ps.ID().String(),
		tenantID,
		ps.Name(),
		ps.Slug(),
		ps.Description(),
		ps.SetType().String(),
		parentSetID,
		clonedFromVersion,
		ps.IsActive(),
		ps.CreatedAt(),
		ps.UpdatedAt(),
	)
	if err != nil {
		if strings.Contains(err.Error(), "uq_permission_sets_slug") {
			return permissionset.ErrPermissionSetSlugExists
		}
		return fmt.Errorf("failed to create permission set: %w", err)
	}

	return nil
}

// GetByID retrieves a permission set by ID.
func (r *PermissionSetRepository) GetByID(ctx context.Context, id shared.ID) (*permissionset.PermissionSet, error) {
	query := `
		SELECT id, tenant_id, name, slug, description, set_type,
			   parent_set_id, cloned_from_version, is_active, created_at, updated_at
		FROM permission_sets
		WHERE id = $1
	`

	return r.scanPermissionSet(r.db.QueryRowContext(ctx, query, id.String()))
}

// GetBySlug retrieves a permission set by tenant and slug.
func (r *PermissionSetRepository) GetBySlug(ctx context.Context, tenantID *shared.ID, slug string) (*permissionset.PermissionSet, error) {
	var query string
	var args []interface{}

	if tenantID == nil {
		query = `
			SELECT id, tenant_id, name, slug, description, set_type,
				   parent_set_id, cloned_from_version, is_active, created_at, updated_at
			FROM permission_sets
			WHERE tenant_id IS NULL AND slug = $1
		`
		args = []interface{}{slug}
	} else {
		query = `
			SELECT id, tenant_id, name, slug, description, set_type,
				   parent_set_id, cloned_from_version, is_active, created_at, updated_at
			FROM permission_sets
			WHERE tenant_id = $1 AND slug = $2
		`
		args = []interface{}{tenantID.String(), slug}
	}

	return r.scanPermissionSet(r.db.QueryRowContext(ctx, query, args...))
}

// Update updates an existing permission set.
func (r *PermissionSetRepository) Update(ctx context.Context, ps *permissionset.PermissionSet) error {
	if ps.IsSystem() {
		return permissionset.ErrSystemSetImmutable
	}

	query := `
		UPDATE permission_sets
		SET name = $2, slug = $3, description = $4, is_active = $5, updated_at = $6
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		ps.ID().String(),
		ps.Name(),
		ps.Slug(),
		ps.Description(),
		ps.IsActive(),
		ps.UpdatedAt(),
	)
	if err != nil {
		if strings.Contains(err.Error(), "uq_permission_sets_slug") {
			return permissionset.ErrPermissionSetSlugExists
		}
		return fmt.Errorf("failed to update permission set: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return permissionset.ErrPermissionSetNotFound
	}

	return nil
}

// Delete removes a permission set.
func (r *PermissionSetRepository) Delete(ctx context.Context, id shared.ID) error {
	// First check if it's a system set
	ps, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if ps.IsSystem() {
		return permissionset.ErrCannotDeleteSystemSet
	}

	// Check if in use
	count, err := r.CountGroupsUsing(ctx, id)
	if err != nil {
		return err
	}
	if count > 0 {
		return permissionset.ErrPermissionSetInUse
	}

	query := `DELETE FROM permission_sets WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete permission set: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return permissionset.ErrPermissionSetNotFound
	}

	return nil
}

// =============================================================================
// Permission Set Query Operations
// =============================================================================

// List lists permission sets with filtering.
func (r *PermissionSetRepository) List(ctx context.Context, filter permissionset.ListFilter) ([]*permissionset.PermissionSet, error) {
	query, args := r.buildListQuery(filter, false)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list permission sets: %w", err)
	}
	defer rows.Close()

	var sets []*permissionset.PermissionSet
	for rows.Next() {
		ps, err := r.scanPermissionSetRow(rows)
		if err != nil {
			return nil, err
		}
		sets = append(sets, ps)
	}

	return sets, rows.Err()
}

// Count counts permission sets with filtering.
func (r *PermissionSetRepository) Count(ctx context.Context, filter permissionset.ListFilter) (int64, error) {
	query, args := r.buildListQuery(filter, true)

	var count int64
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count permission sets: %w", err)
	}

	return count, nil
}

// ExistsBySlug checks if a permission set with the given slug exists.
func (r *PermissionSetRepository) ExistsBySlug(ctx context.Context, tenantID *shared.ID, slug string) (bool, error) {
	var query string
	var args []interface{}

	if tenantID == nil {
		query = `SELECT EXISTS(SELECT 1 FROM permission_sets WHERE tenant_id IS NULL AND slug = $1)`
		args = []interface{}{slug}
	} else {
		query = `SELECT EXISTS(SELECT 1 FROM permission_sets WHERE tenant_id = $1 AND slug = $2)`
		args = []interface{}{tenantID.String(), slug}
	}

	var exists bool
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check slug existence: %w", err)
	}

	return exists, nil
}

// ListByIDs retrieves multiple permission sets by their IDs.
func (r *PermissionSetRepository) ListByIDs(ctx context.Context, ids []shared.ID) ([]*permissionset.PermissionSet, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id.String()
	}

	query := fmt.Sprintf(`
		SELECT id, tenant_id, name, slug, description, set_type,
			   parent_set_id, cloned_from_version, is_active, created_at, updated_at
		FROM permission_sets
		WHERE id IN (%s)
	`, strings.Join(placeholders, ", "))

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list permission sets by IDs: %w", err)
	}
	defer rows.Close()

	var sets []*permissionset.PermissionSet
	for rows.Next() {
		ps, err := r.scanPermissionSetRow(rows)
		if err != nil {
			return nil, err
		}
		sets = append(sets, ps)
	}

	return sets, rows.Err()
}

// ListSystemSets returns all system permission sets.
func (r *PermissionSetRepository) ListSystemSets(ctx context.Context) ([]*permissionset.PermissionSet, error) {
	query := `
		SELECT id, tenant_id, name, slug, description, set_type,
			   parent_set_id, cloned_from_version, is_active, created_at, updated_at
		FROM permission_sets
		WHERE set_type = 'system'
		ORDER BY name ASC
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list system sets: %w", err)
	}
	defer rows.Close()

	var sets []*permissionset.PermissionSet
	for rows.Next() {
		ps, err := r.scanPermissionSetRow(rows)
		if err != nil {
			return nil, err
		}
		sets = append(sets, ps)
	}

	return sets, rows.Err()
}

// ListByTenant returns permission sets for a tenant, optionally including system sets.
func (r *PermissionSetRepository) ListByTenant(ctx context.Context, tenantID shared.ID, includeSystem bool) ([]*permissionset.PermissionSet, error) {
	var query string
	if includeSystem {
		query = `
			SELECT id, tenant_id, name, slug, description, set_type,
				   parent_set_id, cloned_from_version, is_active, created_at, updated_at
			FROM permission_sets
			WHERE tenant_id = $1 OR tenant_id IS NULL
			ORDER BY set_type ASC, name ASC
		`
	} else {
		query = `
			SELECT id, tenant_id, name, slug, description, set_type,
				   parent_set_id, cloned_from_version, is_active, created_at, updated_at
			FROM permission_sets
			WHERE tenant_id = $1
			ORDER BY name ASC
		`
	}

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list permission sets by tenant: %w", err)
	}
	defer rows.Close()

	var sets []*permissionset.PermissionSet
	for rows.Next() {
		ps, err := r.scanPermissionSetRow(rows)
		if err != nil {
			return nil, err
		}
		sets = append(sets, ps)
	}

	return sets, rows.Err()
}

// =============================================================================
// Permission Set Items
// =============================================================================

// AddItem adds a permission to a permission set.
func (r *PermissionSetRepository) AddItem(ctx context.Context, item *permissionset.Item) error {
	query := `
		INSERT INTO permission_set_items (permission_set_id, permission_id, modification_type)
		VALUES ($1, $2, $3)
		ON CONFLICT (permission_set_id, permission_id) DO UPDATE
		SET modification_type = EXCLUDED.modification_type
	`

	_, err := r.db.ExecContext(ctx, query,
		item.PermissionSetID().String(),
		item.PermissionID(),
		item.ModificationType().String(),
	)
	if err != nil {
		return fmt.Errorf("failed to add permission set item: %w", err)
	}

	return nil
}

// RemoveItem removes a permission from a permission set.
func (r *PermissionSetRepository) RemoveItem(ctx context.Context, permissionSetID shared.ID, permissionID string) error {
	query := `DELETE FROM permission_set_items WHERE permission_set_id = $1 AND permission_id = $2`

	_, err := r.db.ExecContext(ctx, query, permissionSetID.String(), permissionID)
	if err != nil {
		return fmt.Errorf("failed to remove permission set item: %w", err)
	}

	return nil
}

// ListItems lists all items in a permission set.
func (r *PermissionSetRepository) ListItems(ctx context.Context, permissionSetID shared.ID) ([]*permissionset.Item, error) {
	query := `
		SELECT permission_set_id, permission_id, modification_type
		FROM permission_set_items
		WHERE permission_set_id = $1
	`

	rows, err := r.db.QueryContext(ctx, query, permissionSetID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list permission set items: %w", err)
	}
	defer rows.Close()

	var items []*permissionset.Item
	for rows.Next() {
		var psIDStr, permID, modTypeStr string
		if err := rows.Scan(&psIDStr, &permID, &modTypeStr); err != nil {
			return nil, fmt.Errorf("failed to scan item: %w", err)
		}

		psID, _ := shared.IDFromString(psIDStr)
		modType := permissionset.ModificationType(modTypeStr)
		items = append(items, permissionset.ReconstituteItem(psID, permID, modType))
	}

	return items, rows.Err()
}

// GetWithItems retrieves a permission set with its items.
func (r *PermissionSetRepository) GetWithItems(ctx context.Context, id shared.ID) (*permissionset.PermissionSetWithItems, error) {
	ps, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	items, err := r.ListItems(ctx, id)
	if err != nil {
		return nil, err
	}

	return &permissionset.PermissionSetWithItems{
		PermissionSet: ps,
		Items:         items,
	}, nil
}

// BatchAddItems adds multiple items to a permission set.
func (r *PermissionSetRepository) BatchAddItems(ctx context.Context, items []*permissionset.Item) error {
	if len(items) == 0 {
		return nil
	}

	query := `
		INSERT INTO permission_set_items (permission_set_id, permission_id, modification_type)
		VALUES ($1, $2, $3)
		ON CONFLICT (permission_set_id, permission_id) DO UPDATE
		SET modification_type = EXCLUDED.modification_type
	`

	for _, item := range items {
		_, err := r.db.ExecContext(ctx, query,
			item.PermissionSetID().String(),
			item.PermissionID(),
			item.ModificationType().String(),
		)
		if err != nil {
			return fmt.Errorf("failed to add item %s: %w", item.PermissionID(), err)
		}
	}

	return nil
}

// ReplaceItems replaces all items in a permission set.
func (r *PermissionSetRepository) ReplaceItems(ctx context.Context, permissionSetID shared.ID, items []*permissionset.Item) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		// Delete existing items
		_, err := tx.ExecContext(ctx, "DELETE FROM permission_set_items WHERE permission_set_id = $1", permissionSetID.String())
		if err != nil {
			return fmt.Errorf("failed to delete existing items: %w", err)
		}

		// Insert new items
		if len(items) == 0 {
			return nil
		}

		query := `
			INSERT INTO permission_set_items (permission_set_id, permission_id, modification_type)
			VALUES ($1, $2, $3)
		`

		for _, item := range items {
			_, err := tx.ExecContext(ctx, query,
				item.PermissionSetID().String(),
				item.PermissionID(),
				item.ModificationType().String(),
			)
			if err != nil {
				return fmt.Errorf("failed to insert item %s: %w", item.PermissionID(), err)
			}
		}

		return nil
	})
}

// =============================================================================
// Version Tracking
// =============================================================================

// CreateVersion creates a new version record.
func (r *PermissionSetRepository) CreateVersion(ctx context.Context, version *permissionset.Version) error {
	changesJSON, err := json.Marshal(version.Changes())
	if err != nil {
		return fmt.Errorf("failed to marshal changes: %w", err)
	}

	query := `
		INSERT INTO permission_set_versions (permission_set_id, version, changes, changed_at, changed_by)
		VALUES ($1, $2, $3, $4, $5)
	`

	var changedBy sql.NullString
	if version.ChangedBy() != nil {
		changedBy = sql.NullString{String: version.ChangedBy().String(), Valid: true}
	}

	_, err = r.db.ExecContext(ctx, query,
		version.PermissionSetID().String(),
		version.Version(),
		changesJSON,
		version.ChangedAt(),
		changedBy,
	)
	if err != nil {
		if strings.Contains(err.Error(), "permission_set_versions_pkey") {
			return permissionset.ErrVersionConflict
		}
		return fmt.Errorf("failed to create version: %w", err)
	}

	return nil
}

// GetLatestVersion retrieves the latest version for a permission set.
func (r *PermissionSetRepository) GetLatestVersion(ctx context.Context, permissionSetID shared.ID) (*permissionset.Version, error) {
	query := `
		SELECT permission_set_id, version, changes, changed_at, changed_by
		FROM permission_set_versions
		WHERE permission_set_id = $1
		ORDER BY version DESC
		LIMIT 1
	`

	return r.scanVersion(r.db.QueryRowContext(ctx, query, permissionSetID.String()))
}

// ListVersions lists all versions for a permission set.
func (r *PermissionSetRepository) ListVersions(ctx context.Context, permissionSetID shared.ID) ([]*permissionset.Version, error) {
	query := `
		SELECT permission_set_id, version, changes, changed_at, changed_by
		FROM permission_set_versions
		WHERE permission_set_id = $1
		ORDER BY version DESC
	`

	rows, err := r.db.QueryContext(ctx, query, permissionSetID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list versions: %w", err)
	}
	defer rows.Close()

	var versions []*permissionset.Version
	for rows.Next() {
		v, err := r.scanVersionRow(rows)
		if err != nil {
			return nil, err
		}
		versions = append(versions, v)
	}

	return versions, rows.Err()
}

// =============================================================================
// Inheritance Queries
// =============================================================================

// GetParent retrieves the parent of a permission set.
func (r *PermissionSetRepository) GetParent(ctx context.Context, permissionSetID shared.ID) (*permissionset.PermissionSet, error) {
	query := `
		SELECT p.id, p.tenant_id, p.name, p.slug, p.description, p.set_type,
			   p.parent_set_id, p.cloned_from_version, p.is_active, p.created_at, p.updated_at
		FROM permission_sets ps
		INNER JOIN permission_sets p ON ps.parent_set_id = p.id
		WHERE ps.id = $1
	`

	return r.scanPermissionSet(r.db.QueryRowContext(ctx, query, permissionSetID.String()))
}

// ListChildren retrieves all children of a permission set.
func (r *PermissionSetRepository) ListChildren(ctx context.Context, parentSetID shared.ID) ([]*permissionset.PermissionSet, error) {
	query := `
		SELECT id, tenant_id, name, slug, description, set_type,
			   parent_set_id, cloned_from_version, is_active, created_at, updated_at
		FROM permission_sets
		WHERE parent_set_id = $1
		ORDER BY name ASC
	`

	rows, err := r.db.QueryContext(ctx, query, parentSetID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list children: %w", err)
	}
	defer rows.Close()

	var sets []*permissionset.PermissionSet
	for rows.Next() {
		ps, err := r.scanPermissionSetRow(rows)
		if err != nil {
			return nil, err
		}
		sets = append(sets, ps)
	}

	return sets, rows.Err()
}

// GetInheritanceChain retrieves the full inheritance chain for a permission set.
func (r *PermissionSetRepository) GetInheritanceChain(ctx context.Context, permissionSetID shared.ID) ([]*permissionset.PermissionSet, error) {
	// Use recursive CTE to get the full chain
	query := `
		WITH RECURSIVE chain AS (
			SELECT id, tenant_id, name, slug, description, set_type,
				   parent_set_id, cloned_from_version, is_active, created_at, updated_at, 0 as depth
			FROM permission_sets
			WHERE id = $1

			UNION ALL

			SELECT p.id, p.tenant_id, p.name, p.slug, p.description, p.set_type,
				   p.parent_set_id, p.cloned_from_version, p.is_active, p.created_at, p.updated_at, c.depth + 1
			FROM permission_sets p
			INNER JOIN chain c ON p.id = c.parent_set_id
			WHERE c.depth < 10  -- Prevent infinite loops
		)
		SELECT id, tenant_id, name, slug, description, set_type,
			   parent_set_id, cloned_from_version, is_active, created_at, updated_at
		FROM chain
		ORDER BY depth DESC  -- Root first
	`

	rows, err := r.db.QueryContext(ctx, query, permissionSetID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get inheritance chain: %w", err)
	}
	defer rows.Close()

	var sets []*permissionset.PermissionSet
	for rows.Next() {
		ps, err := r.scanPermissionSetRow(rows)
		if err != nil {
			return nil, err
		}
		sets = append(sets, ps)
	}

	return sets, rows.Err()
}

// =============================================================================
// Usage Queries
// =============================================================================

// CountGroupsUsing counts groups using a permission set.
func (r *PermissionSetRepository) CountGroupsUsing(ctx context.Context, permissionSetID shared.ID) (int64, error) {
	query := `SELECT COUNT(*) FROM group_permission_sets WHERE permission_set_id = $1`

	var count int64
	err := r.db.QueryRowContext(ctx, query, permissionSetID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count groups using permission set: %w", err)
	}

	return count, nil
}

// ListGroupIDsUsing lists group IDs using a permission set.
func (r *PermissionSetRepository) ListGroupIDsUsing(ctx context.Context, permissionSetID shared.ID) ([]shared.ID, error) {
	query := `SELECT group_id FROM group_permission_sets WHERE permission_set_id = $1`

	rows, err := r.db.QueryContext(ctx, query, permissionSetID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list group IDs: %w", err)
	}
	defer rows.Close()

	var ids []shared.ID
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return nil, fmt.Errorf("failed to scan group ID: %w", err)
		}
		id, _ := shared.IDFromString(idStr)
		ids = append(ids, id)
	}

	return ids, rows.Err()
}

// =============================================================================
// Helper Functions
// =============================================================================

func (r *PermissionSetRepository) buildListQuery(filter permissionset.ListFilter, countOnly bool) (string, []interface{}) {
	var (
		conditions []string
		args       []interface{}
		argIndex   = 1
	)

	// Tenant filter
	if filter.TenantID != nil {
		if filter.IncludeSystem {
			conditions = append(conditions, fmt.Sprintf("(tenant_id = $%d OR tenant_id IS NULL)", argIndex))
		} else {
			conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		}
		args = append(args, filter.TenantID.String())
		argIndex++
	} else if !filter.IncludeSystem {
		conditions = append(conditions, "tenant_id IS NULL")
	}

	// Type filter
	if len(filter.SetTypes) > 0 {
		placeholders := make([]string, len(filter.SetTypes))
		for i, st := range filter.SetTypes {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, st.String())
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("set_type IN (%s)", strings.Join(placeholders, ", ")))
	}

	// Search filter
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR slug ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex, argIndex))
		args = append(args, wrapLikePattern(filter.Search))
		argIndex++
	}

	// Active filter
	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argIndex))
		args = append(args, *filter.IsActive)
		argIndex++
	}

	// Parent filter
	if filter.ParentSetID != nil {
		conditions = append(conditions, fmt.Sprintf("parent_set_id = $%d", argIndex))
		args = append(args, filter.ParentSetID.String())
		argIndex++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	if countOnly {
		return fmt.Sprintf("SELECT COUNT(*) FROM permission_sets %s", whereClause), args
	}

	// Build SELECT query with ordering and pagination
	// SECURITY: Use allowlist to prevent SQL injection via ORDER BY
	orderBy := sortFieldName
	switch filter.OrderBy {
	case sortFieldName, "slug", sortFieldCreatedAt, sortFieldUpdatedAt, "set_type":
		orderBy = filter.OrderBy
	}
	orderDir := sortOrderASC
	if filter.OrderDesc {
		orderDir = sortOrderDESC
	}

	query := fmt.Sprintf(`
		SELECT id, tenant_id, name, slug, description, set_type,
			   parent_set_id, cloned_from_version, is_active, created_at, updated_at
		FROM permission_sets
		%s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderBy, orderDir, argIndex, argIndex+1)

	args = append(args, filter.Limit, filter.Offset)

	return query, args
}

func (r *PermissionSetRepository) scanPermissionSet(row *sql.Row) (*permissionset.PermissionSet, error) {
	var (
		idStr, name, slug, setTypeStr string
		tenantIDStr, parentSetIDStr   sql.NullString
		description                   sql.NullString
		clonedFromVersion             sql.NullInt32
		isActive                      bool
		createdAt, updatedAt          time.Time
	)

	err := row.Scan(
		&idStr, &tenantIDStr, &name, &slug, &description, &setTypeStr,
		&parentSetIDStr, &clonedFromVersion, &isActive, &createdAt, &updatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, permissionset.ErrPermissionSetNotFound
		}
		return nil, fmt.Errorf("failed to scan permission set: %w", err)
	}

	return r.reconstitutePermissionSet(
		idStr, tenantIDStr, name, slug, description.String, setTypeStr,
		parentSetIDStr, clonedFromVersion, isActive, createdAt, updatedAt,
	), nil
}

func (r *PermissionSetRepository) scanPermissionSetRow(rows *sql.Rows) (*permissionset.PermissionSet, error) {
	var (
		idStr, name, slug, setTypeStr string
		tenantIDStr, parentSetIDStr   sql.NullString
		description                   sql.NullString
		clonedFromVersion             sql.NullInt32
		isActive                      bool
		createdAt, updatedAt          time.Time
	)

	err := rows.Scan(
		&idStr, &tenantIDStr, &name, &slug, &description, &setTypeStr,
		&parentSetIDStr, &clonedFromVersion, &isActive, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan permission set: %w", err)
	}

	return r.reconstitutePermissionSet(
		idStr, tenantIDStr, name, slug, description.String, setTypeStr,
		parentSetIDStr, clonedFromVersion, isActive, createdAt, updatedAt,
	), nil
}

func (r *PermissionSetRepository) reconstitutePermissionSet(
	idStr string,
	tenantIDStr sql.NullString,
	name, slug, description, setTypeStr string,
	parentSetIDStr sql.NullString,
	clonedFromVersion sql.NullInt32,
	isActive bool,
	createdAt, updatedAt time.Time,
) *permissionset.PermissionSet {
	id, _ := shared.IDFromString(idStr)
	setType := permissionset.SetType(setTypeStr)

	var tenantID *shared.ID
	if tenantIDStr.Valid {
		parsed, _ := shared.IDFromString(tenantIDStr.String)
		tenantID = &parsed
	}

	var parentSetID *shared.ID
	if parentSetIDStr.Valid {
		parsed, _ := shared.IDFromString(parentSetIDStr.String)
		parentSetID = &parsed
	}

	var clonedVersion *int
	if clonedFromVersion.Valid {
		v := int(clonedFromVersion.Int32)
		clonedVersion = &v
	}

	return permissionset.Reconstitute(
		id, tenantID, name, slug, description, setType,
		parentSetID, clonedVersion, isActive, createdAt, updatedAt,
	)
}

func (r *PermissionSetRepository) scanVersion(row *sql.Row) (*permissionset.Version, error) {
	var (
		psIDStr, changedByStr sql.NullString
		version               int
		changesJSON           []byte
		changedAt             time.Time
	)

	err := row.Scan(&psIDStr, &version, &changesJSON, &changedAt, &changedByStr)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, permissionset.ErrPermissionSetNotFound
		}
		return nil, fmt.Errorf("failed to scan version: %w", err)
	}

	psID, _ := shared.IDFromString(psIDStr.String)

	var changes permissionset.VersionChanges
	if err := json.Unmarshal(changesJSON, &changes); err != nil {
		changes = permissionset.VersionChanges{}
	}

	var changedBy *shared.ID
	if changedByStr.Valid {
		parsed, _ := shared.IDFromString(changedByStr.String)
		changedBy = &parsed
	}

	return permissionset.ReconstituteVersion(psID, version, changes, changedAt, changedBy), nil
}

func (r *PermissionSetRepository) scanVersionRow(rows *sql.Rows) (*permissionset.Version, error) {
	var (
		psIDStr     string
		changedBy   sql.NullString
		version     int
		changesJSON []byte
		changedAt   time.Time
	)

	err := rows.Scan(&psIDStr, &version, &changesJSON, &changedAt, &changedBy)
	if err != nil {
		return nil, fmt.Errorf("failed to scan version: %w", err)
	}

	psID, _ := shared.IDFromString(psIDStr)

	var changes permissionset.VersionChanges
	if err := json.Unmarshal(changesJSON, &changes); err != nil {
		changes = permissionset.VersionChanges{}
	}

	var changedByID *shared.ID
	if changedBy.Valid {
		parsed, _ := shared.IDFromString(changedBy.String)
		changedByID = &parsed
	}

	return permissionset.ReconstituteVersion(psID, version, changes, changedAt, changedByID), nil
}
