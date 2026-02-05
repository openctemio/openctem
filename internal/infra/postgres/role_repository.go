package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/role"
)

// RoleRepository implements role.Repository using PostgreSQL.
type RoleRepository struct {
	db *DB
}

// NewRoleRepository creates a new RoleRepository.
func NewRoleRepository(db *DB) *RoleRepository {
	return &RoleRepository{db: db}
}

// Create persists a new role.
func (r *RoleRepository) Create(ctx context.Context, ro *role.Role) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Insert role
	query := `
		INSERT INTO roles (id, tenant_id, slug, name, description, is_system,
		                   hierarchy_level, has_full_data_access, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	var tenantID sql.NullString
	if ro.TenantID() != nil {
		tenantID = sql.NullString{String: ro.TenantID().String(), Valid: true}
	}

	var createdBy sql.NullString
	if ro.CreatedBy() != nil {
		createdBy = sql.NullString{String: ro.CreatedBy().String(), Valid: true}
	}

	_, err = tx.ExecContext(ctx, query,
		ro.ID().String(),
		tenantID,
		ro.Slug(),
		ro.Name(),
		ro.Description(),
		ro.IsSystem(),
		ro.HierarchyLevel(),
		ro.HasFullDataAccess(),
		createdBy,
		ro.CreatedAt(),
		ro.UpdatedAt(),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return role.ErrRoleSlugExists
		}
		return fmt.Errorf("failed to create role: %w", err)
	}

	// Insert role permissions using batch insert
	if err := r.insertPermissionsBatch(ctx, tx, ro.ID().String(), ro.Permissions()); err != nil {
		return err
	}

	return tx.Commit()
}

// GetByID retrieves a role by its ID.
func (r *RoleRepository) GetByID(ctx context.Context, id role.ID) (*role.Role, error) {
	query := `
		SELECT id, tenant_id, slug, name, description, is_system,
		       hierarchy_level, has_full_data_access, created_at, updated_at, created_by
		FROM roles
		WHERE id = $1
	`

	var (
		roleID            string
		tenantID          sql.NullString
		slug              string
		name              string
		description       sql.NullString
		isSystem          bool
		hierarchyLevel    int
		hasFullDataAccess bool
		createdAt         time.Time
		updatedAt         time.Time
		createdBy         sql.NullString
	)

	err := r.db.QueryRowContext(ctx, query, id.String()).Scan(
		&roleID, &tenantID, &slug, &name, &description,
		&isSystem, &hierarchyLevel, &hasFullDataAccess,
		&createdAt, &updatedAt, &createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, role.ErrRoleNotFound
		}
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	// Get permissions
	permissions, err := r.getPermissions(ctx, id)
	if err != nil {
		return nil, err
	}

	return r.reconstructRole(roleID, tenantID, slug, name, description,
		isSystem, hierarchyLevel, hasFullDataAccess,
		permissions, createdAt, updatedAt, createdBy)
}

// GetBySlug retrieves a role by slug.
func (r *RoleRepository) GetBySlug(ctx context.Context, tenantID *role.ID, slug string) (*role.Role, error) {
	var query string
	var args []any

	if tenantID == nil {
		// System role
		query = `
			SELECT id, tenant_id, slug, name, description, is_system,
			       hierarchy_level, has_full_data_access, created_at, updated_at, created_by
			FROM roles
			WHERE slug = $1 AND tenant_id IS NULL
		`
		args = []any{slug}
	} else {
		// Tenant role
		query = `
			SELECT id, tenant_id, slug, name, description, is_system,
			       hierarchy_level, has_full_data_access, created_at, updated_at, created_by
			FROM roles
			WHERE slug = $1 AND tenant_id = $2
		`
		args = []any{slug, tenantID.String()}
	}

	var (
		roleID            string
		dbTenantID        sql.NullString
		dbSlug            string
		name              string
		description       sql.NullString
		isSystem          bool
		hierarchyLevel    int
		hasFullDataAccess bool
		createdAt         time.Time
		updatedAt         time.Time
		createdBy         sql.NullString
	)

	err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&roleID, &dbTenantID, &dbSlug, &name, &description,
		&isSystem, &hierarchyLevel, &hasFullDataAccess,
		&createdAt, &updatedAt, &createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, role.ErrRoleNotFound
		}
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	id, _ := role.ParseID(roleID)
	permissions, err := r.getPermissions(ctx, id)
	if err != nil {
		return nil, err
	}

	return r.reconstructRole(roleID, dbTenantID, dbSlug, name, description,
		isSystem, hierarchyLevel, hasFullDataAccess,
		permissions, createdAt, updatedAt, createdBy)
}

// ListForTenant returns all roles available for a tenant.
// OPTIMIZED: Uses batch permission loading to avoid N+1 queries.
func (r *RoleRepository) ListForTenant(ctx context.Context, tenantID role.ID) ([]*role.Role, error) {
	query := `
		SELECT id, tenant_id, slug, name, description, is_system,
		       hierarchy_level, has_full_data_access, created_at, updated_at, created_by
		FROM roles
		WHERE tenant_id IS NULL OR tenant_id = $1
		ORDER BY hierarchy_level DESC, name ASC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}
	defer rows.Close()

	// First pass: collect role data and IDs
	type roleData struct {
		roleID            string
		dbTenantID        sql.NullString
		slug              string
		name              string
		description       sql.NullString
		isSystem          bool
		hierarchyLevel    int
		hasFullDataAccess bool
		createdAt         time.Time
		updatedAt         time.Time
		createdBy         sql.NullString
	}

	var roleDataList []roleData
	var roleIDs []string

	for rows.Next() {
		var rd roleData
		if err := rows.Scan(&rd.roleID, &rd.dbTenantID, &rd.slug, &rd.name, &rd.description,
			&rd.isSystem, &rd.hierarchyLevel, &rd.hasFullDataAccess,
			&rd.createdAt, &rd.updatedAt, &rd.createdBy); err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roleDataList = append(roleDataList, rd)
		roleIDs = append(roleIDs, rd.roleID)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Batch load all permissions in single query
	permissionsMap, err := r.getPermissionsBatch(ctx, roleIDs)
	if err != nil {
		return nil, err
	}

	// Second pass: reconstruct roles with permissions
	roles := make([]*role.Role, 0, len(roleDataList))
	for _, rd := range roleDataList {
		permissions := permissionsMap[rd.roleID]

		ro, err := r.reconstructRole(rd.roleID, rd.dbTenantID, rd.slug, rd.name, rd.description,
			rd.isSystem, rd.hierarchyLevel, rd.hasFullDataAccess,
			permissions, rd.createdAt, rd.updatedAt, rd.createdBy)
		if err != nil {
			return nil, err
		}
		roles = append(roles, ro)
	}

	return roles, nil
}

// ListSystemRoles returns only system roles.
// OPTIMIZED: Uses batch permission loading to avoid N+1 queries.
func (r *RoleRepository) ListSystemRoles(ctx context.Context) ([]*role.Role, error) {
	query := `
		SELECT id, tenant_id, slug, name, description, is_system,
		       hierarchy_level, has_full_data_access, created_at, updated_at, created_by
		FROM roles
		WHERE is_system = TRUE AND tenant_id IS NULL
		ORDER BY hierarchy_level DESC
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list system roles: %w", err)
	}
	defer rows.Close()

	// First pass: collect role data and IDs
	type roleData struct {
		roleID            string
		dbTenantID        sql.NullString
		slug              string
		name              string
		description       sql.NullString
		isSystem          bool
		hierarchyLevel    int
		hasFullDataAccess bool
		createdAt         time.Time
		updatedAt         time.Time
		createdBy         sql.NullString
	}

	var roleDataList []roleData
	var roleIDs []string

	for rows.Next() {
		var rd roleData
		if err := rows.Scan(&rd.roleID, &rd.dbTenantID, &rd.slug, &rd.name, &rd.description,
			&rd.isSystem, &rd.hierarchyLevel, &rd.hasFullDataAccess,
			&rd.createdAt, &rd.updatedAt, &rd.createdBy); err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roleDataList = append(roleDataList, rd)
		roleIDs = append(roleIDs, rd.roleID)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Batch load all permissions in single query
	permissionsMap, err := r.getPermissionsBatch(ctx, roleIDs)
	if err != nil {
		return nil, err
	}

	// Second pass: reconstruct roles with permissions
	roles := make([]*role.Role, 0, len(roleDataList))
	for _, rd := range roleDataList {
		permissions := permissionsMap[rd.roleID]

		ro, err := r.reconstructRole(rd.roleID, rd.dbTenantID, rd.slug, rd.name, rd.description,
			rd.isSystem, rd.hierarchyLevel, rd.hasFullDataAccess,
			permissions, rd.createdAt, rd.updatedAt, rd.createdBy)
		if err != nil {
			return nil, err
		}
		roles = append(roles, ro)
	}

	return roles, nil
}

// Update updates a role.
func (r *RoleRepository) Update(ctx context.Context, ro *role.Role) error {
	if ro.IsSystem() {
		return role.ErrCannotModifySystemRole
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Update role
	query := `
		UPDATE roles
		SET name = $2, description = $3, hierarchy_level = $4,
		    has_full_data_access = $5, updated_at = $6
		WHERE id = $1 AND is_system = FALSE
	`

	result, err := tx.ExecContext(ctx, query,
		ro.ID().String(),
		ro.Name(),
		ro.Description(),
		ro.HierarchyLevel(),
		ro.HasFullDataAccess(),
		ro.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return role.ErrRoleNotFound
	}

	// Replace permissions - delete old and batch insert new
	_, err = tx.ExecContext(ctx, "DELETE FROM role_permissions WHERE role_id = $1", ro.ID().String())
	if err != nil {
		return fmt.Errorf("failed to delete old permissions: %w", err)
	}

	if err := r.insertPermissionsBatch(ctx, tx, ro.ID().String(), ro.Permissions()); err != nil {
		return err
	}

	return tx.Commit()
}

// Delete deletes a role.
func (r *RoleRepository) Delete(ctx context.Context, id role.ID) error {
	// Check if it's a system role
	var isSystem bool
	err := r.db.QueryRowContext(ctx, "SELECT is_system FROM roles WHERE id = $1", id.String()).Scan(&isSystem)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return role.ErrRoleNotFound
		}
		return fmt.Errorf("failed to check role: %w", err)
	}

	if isSystem {
		return role.ErrCannotDeleteSystemRole
	}

	// Check if role is in use
	count, err := r.CountUsersWithRole(ctx, id)
	if err != nil {
		return err
	}
	if count > 0 {
		return role.ErrRoleInUse
	}

	// Delete (cascade will handle role_permissions)
	_, err = r.db.ExecContext(ctx, "DELETE FROM roles WHERE id = $1", id.String())
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	return nil
}

// GetUserRoles returns all roles for a user in a tenant.
// OPTIMIZED: Uses batch permission loading to avoid N+1 queries.
func (r *RoleRepository) GetUserRoles(ctx context.Context, tenantID, userID role.ID) ([]*role.Role, error) {
	query := `
		SELECT r.id, r.tenant_id, r.slug, r.name, r.description, r.is_system,
		       r.hierarchy_level, r.has_full_data_access, r.created_at, r.updated_at, r.created_by
		FROM roles r
		JOIN user_roles ur ON ur.role_id = r.id
		WHERE ur.tenant_id = $1 AND ur.user_id = $2
		ORDER BY r.hierarchy_level DESC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), userID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	defer rows.Close()

	// First pass: collect role data and IDs
	type roleData struct {
		roleID            string
		dbTenantID        sql.NullString
		slug              string
		name              string
		description       sql.NullString
		isSystem          bool
		hierarchyLevel    int
		hasFullDataAccess bool
		createdAt         time.Time
		updatedAt         time.Time
		createdBy         sql.NullString
	}

	var roleDataList []roleData
	var roleIDs []string

	for rows.Next() {
		var rd roleData
		if err := rows.Scan(&rd.roleID, &rd.dbTenantID, &rd.slug, &rd.name, &rd.description,
			&rd.isSystem, &rd.hierarchyLevel, &rd.hasFullDataAccess,
			&rd.createdAt, &rd.updatedAt, &rd.createdBy); err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roleDataList = append(roleDataList, rd)
		roleIDs = append(roleIDs, rd.roleID)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Batch load all permissions in single query
	permissionsMap, err := r.getPermissionsBatch(ctx, roleIDs)
	if err != nil {
		return nil, err
	}

	// Second pass: reconstruct roles with permissions
	roles := make([]*role.Role, 0, len(roleDataList))
	for _, rd := range roleDataList {
		permissions := permissionsMap[rd.roleID]

		ro, err := r.reconstructRole(rd.roleID, rd.dbTenantID, rd.slug, rd.name, rd.description,
			rd.isSystem, rd.hierarchyLevel, rd.hasFullDataAccess,
			permissions, rd.createdAt, rd.updatedAt, rd.createdBy)
		if err != nil {
			return nil, err
		}
		roles = append(roles, ro)
	}

	return roles, nil
}

// GetUserPermissions returns all permissions for a user (UNION of all roles).
func (r *RoleRepository) GetUserPermissions(ctx context.Context, tenantID, userID role.ID) ([]string, error) {
	query := `
		SELECT DISTINCT rp.permission_id
		FROM user_roles ur
		JOIN role_permissions rp ON rp.role_id = ur.role_id
		WHERE ur.tenant_id = $1 AND ur.user_id = $2
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), userID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}
	defer rows.Close()

	var permissions []string
	for rows.Next() {
		var permID string
		if err := rows.Scan(&permID); err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		permissions = append(permissions, permID)
	}

	return permissions, rows.Err()
}

// HasFullDataAccess checks if user has full data access.
func (r *RoleRepository) HasFullDataAccess(ctx context.Context, tenantID, userID role.ID) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM user_roles ur
			JOIN roles r ON r.id = ur.role_id
			WHERE ur.tenant_id = $1 AND ur.user_id = $2 AND r.has_full_data_access = TRUE
		)
	`

	var hasAccess bool
	err := r.db.QueryRowContext(ctx, query, tenantID.String(), userID.String()).Scan(&hasAccess)
	if err != nil {
		return false, fmt.Errorf("failed to check full data access: %w", err)
	}

	return hasAccess, nil
}

// AssignRole assigns a role to a user.
func (r *RoleRepository) AssignRole(ctx context.Context, tenantID, userID, roleID role.ID, assignedBy *role.ID) error {
	query := `
		INSERT INTO user_roles (user_id, tenant_id, role_id, assigned_by, assigned_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id, tenant_id, role_id) DO NOTHING
	`

	var assignedByStr sql.NullString
	if assignedBy != nil {
		assignedByStr = sql.NullString{String: assignedBy.String(), Valid: true}
	}

	_, err := r.db.ExecContext(ctx, query,
		userID.String(),
		tenantID.String(),
		roleID.String(),
		assignedByStr,
		time.Now(),
	)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	return nil
}

// RemoveRole removes a role from a user.
func (r *RoleRepository) RemoveRole(ctx context.Context, tenantID, userID, roleID role.ID) error {
	query := `
		DELETE FROM user_roles
		WHERE tenant_id = $1 AND user_id = $2 AND role_id = $3
	`

	result, err := r.db.ExecContext(ctx, query, tenantID.String(), userID.String(), roleID.String())
	if err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return role.ErrUserRoleNotFound
	}

	return nil
}

// SetUserRoles replaces all roles for a user.
// OPTIMIZED: Uses batch insert instead of inserting one by one.
func (r *RoleRepository) SetUserRoles(ctx context.Context, tenantID, userID role.ID, roleIDs []role.ID, assignedBy *role.ID) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Delete existing roles
	_, err = tx.ExecContext(ctx,
		"DELETE FROM user_roles WHERE tenant_id = $1 AND user_id = $2",
		tenantID.String(), userID.String(),
	)
	if err != nil {
		return fmt.Errorf("failed to delete existing roles: %w", err)
	}

	// Batch insert new roles
	if len(roleIDs) > 0 {
		var assignedByStr sql.NullString
		if assignedBy != nil {
			assignedByStr = sql.NullString{String: assignedBy.String(), Valid: true}
		}

		// Convert role.ID slice to string slice
		roleIDStrs := make([]string, len(roleIDs))
		for i, rid := range roleIDs {
			roleIDStrs[i] = rid.String()
		}

		if err := r.insertUserRolesForUserBatch(ctx, tx, tenantID.String(), userID.String(), roleIDStrs, assignedByStr, time.Now()); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// BulkAssignRoleToUsers assigns a role to multiple users at once.
// OPTIMIZED: Uses batch insert instead of inserting one by one.
func (r *RoleRepository) BulkAssignRoleToUsers(ctx context.Context, tenantID, roleID role.ID, userIDs []role.ID, assignedBy *role.ID) error {
	if len(userIDs) == 0 {
		return nil
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var assignedByStr sql.NullString
	if assignedBy != nil {
		assignedByStr = sql.NullString{String: assignedBy.String(), Valid: true}
	}

	// Convert role.ID slice to string slice
	userIDStrs := make([]string, len(userIDs))
	for i, uid := range userIDs {
		userIDStrs[i] = uid.String()
	}

	// Batch insert all user roles in single query
	if err := r.insertUserRolesBatch(ctx, tx, tenantID.String(), roleID.String(), userIDStrs, assignedByStr, time.Now()); err != nil {
		return err
	}

	return tx.Commit()
}

// ListRoleMembers returns all users who have a specific role.
func (r *RoleRepository) ListRoleMembers(ctx context.Context, tenantID, roleID role.ID) ([]*role.UserRole, error) {
	query := `
		SELECT ur.id, ur.user_id, ur.tenant_id, ur.role_id, ur.assigned_at, ur.assigned_by,
		       u.name, u.email, u.avatar_url
		FROM user_roles ur
		JOIN users u ON u.id = ur.user_id
		WHERE ur.tenant_id = $1 AND ur.role_id = $2
		ORDER BY ur.assigned_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), roleID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list role members: %w", err)
	}
	defer rows.Close()

	var members []*role.UserRole
	for rows.Next() {
		var (
			id            string
			userID        string
			dbTenantID    string
			dbRoleID      string
			assignedAt    time.Time
			assignedBy    sql.NullString
			userName      sql.NullString
			userEmail     string
			userAvatarURL sql.NullString
		)

		if err := rows.Scan(&id, &userID, &dbTenantID, &dbRoleID, &assignedAt, &assignedBy,
			&userName, &userEmail, &userAvatarURL); err != nil {
			return nil, fmt.Errorf("failed to scan user role: %w", err)
		}

		urID, _ := role.ParseID(id)
		urUserID, _ := role.ParseID(userID)
		urTenantID, _ := role.ParseID(dbTenantID)
		urRoleID, _ := role.ParseID(dbRoleID)

		var assignedByID *role.ID
		if assignedBy.Valid {
			id, _ := role.ParseID(assignedBy.String)
			assignedByID = &id
		}

		members = append(members, &role.UserRole{
			ID:            urID,
			UserID:        urUserID,
			TenantID:      urTenantID,
			RoleID:        urRoleID,
			AssignedAt:    assignedAt,
			AssignedBy:    assignedByID,
			UserName:      userName.String,
			UserEmail:     userEmail,
			UserAvatarURL: userAvatarURL.String,
		})
	}

	return members, rows.Err()
}

// CountUsersWithRole returns the count of users with a specific role.
func (r *RoleRepository) CountUsersWithRole(ctx context.Context, roleID role.ID) (int, error) {
	query := `SELECT COUNT(*) FROM user_roles WHERE role_id = $1`

	var count int
	err := r.db.QueryRowContext(ctx, query, roleID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count users: %w", err)
	}

	return count, nil
}

// Helper methods

func (r *RoleRepository) getPermissions(ctx context.Context, roleID role.ID) ([]string, error) {
	query := `SELECT permission_id FROM role_permissions WHERE role_id = $1`

	rows, err := r.db.QueryContext(ctx, query, roleID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions: %w", err)
	}
	defer rows.Close()

	var permissions []string
	for rows.Next() {
		var permID string
		if err := rows.Scan(&permID); err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		permissions = append(permissions, permID)
	}

	return permissions, rows.Err()
}

// getPermissionsBatch fetches permissions for multiple role IDs in a single query.
// Returns a map of roleID -> []permissions to avoid N+1 queries.
func (r *RoleRepository) getPermissionsBatch(ctx context.Context, roleIDs []string) (map[string][]string, error) {
	if len(roleIDs) == 0 {
		return make(map[string][]string), nil
	}

	// Build placeholders for IN clause
	placeholders := make([]string, len(roleIDs))
	args := make([]any, len(roleIDs))
	for i, id := range roleIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}

	query := fmt.Sprintf(`
		SELECT role_id, permission_id
		FROM role_permissions
		WHERE role_id IN (%s)
		ORDER BY role_id, permission_id
	`, joinStrings(placeholders, ", "))

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions batch: %w", err)
	}
	defer rows.Close()

	// Initialize map with empty slices for all roleIDs
	result := make(map[string][]string, len(roleIDs))
	for _, id := range roleIDs {
		result[id] = []string{}
	}

	for rows.Next() {
		var roleID, permID string
		if err := rows.Scan(&roleID, &permID); err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		result[roleID] = append(result[roleID], permID)
	}

	return result, rows.Err()
}

// insertPermissionsBatch inserts multiple permissions for a role in a single query.
func (r *RoleRepository) insertPermissionsBatch(ctx context.Context, tx *sql.Tx, roleID string, permissions []string) error {
	if len(permissions) == 0 {
		return nil
	}

	// Build batch INSERT query
	valueStrings := make([]string, len(permissions))
	valueArgs := make([]any, len(permissions)+1)
	valueArgs[0] = roleID

	for i, permID := range permissions {
		valueStrings[i] = fmt.Sprintf("($1, $%d)", i+2)
		valueArgs[i+1] = permID
	}

	//nolint:gosec // G201: SQL formatting is safe - using parameterized placeholders, not user input
	query := fmt.Sprintf(`
		INSERT INTO role_permissions (role_id, permission_id)
		VALUES %s
	`, joinStrings(valueStrings, ", "))

	_, err := tx.ExecContext(ctx, query, valueArgs...)
	if err != nil {
		return fmt.Errorf("failed to batch insert permissions: %w", err)
	}

	return nil
}

// insertUserRolesBatch inserts multiple user_roles in a single query.
func (r *RoleRepository) insertUserRolesBatch(ctx context.Context, tx *sql.Tx, tenantID, roleID string, userIDs []string, assignedBy sql.NullString, assignedAt time.Time) error {
	if len(userIDs) == 0 {
		return nil
	}

	// Build batch INSERT query with ON CONFLICT
	valueStrings := make([]string, len(userIDs))
	valueArgs := make([]any, 4+len(userIDs))
	valueArgs[0] = tenantID
	valueArgs[1] = roleID
	valueArgs[2] = assignedBy
	valueArgs[3] = assignedAt

	for i, userID := range userIDs {
		valueStrings[i] = fmt.Sprintf("($%d, $1, $2, $3, $4)", i+5)
		valueArgs[i+4] = userID
	}

	//nolint:gosec // G201: SQL formatting is safe - using parameterized placeholders, not user input
	query := fmt.Sprintf(`
		INSERT INTO user_roles (user_id, tenant_id, role_id, assigned_by, assigned_at)
		VALUES %s
		ON CONFLICT (user_id, tenant_id, role_id) DO NOTHING
	`, joinStrings(valueStrings, ", "))

	_, err := tx.ExecContext(ctx, query, valueArgs...)
	if err != nil {
		return fmt.Errorf("failed to batch insert user roles: %w", err)
	}

	return nil
}

// insertUserRolesForUserBatch inserts multiple roles for a single user in a single query.
// Used by SetUserRoles.
func (r *RoleRepository) insertUserRolesForUserBatch(ctx context.Context, tx *sql.Tx, tenantID, userID string, roleIDs []string, assignedBy sql.NullString, assignedAt time.Time) error {
	if len(roleIDs) == 0 {
		return nil
	}

	// Build batch INSERT query
	valueStrings := make([]string, len(roleIDs))
	valueArgs := make([]any, 4+len(roleIDs))
	valueArgs[0] = userID
	valueArgs[1] = tenantID
	valueArgs[2] = assignedBy
	valueArgs[3] = assignedAt

	for i, roleID := range roleIDs {
		valueStrings[i] = fmt.Sprintf("($1, $2, $%d, $3, $4)", i+5)
		valueArgs[i+4] = roleID
	}

	//nolint:gosec // G201: SQL formatting is safe - using parameterized placeholders, not user input
	query := fmt.Sprintf(`
		INSERT INTO user_roles (user_id, tenant_id, role_id, assigned_by, assigned_at)
		VALUES %s
	`, joinStrings(valueStrings, ", "))

	_, err := tx.ExecContext(ctx, query, valueArgs...)
	if err != nil {
		return fmt.Errorf("failed to batch insert user roles: %w", err)
	}

	return nil
}

// joinStrings is defined in dashboard_repository.go (same package)

func (r *RoleRepository) reconstructRole(
	roleID string,
	tenantID sql.NullString,
	slug string,
	name string,
	description sql.NullString,
	isSystem bool,
	hierarchyLevel int,
	hasFullDataAccess bool,
	permissions []string,
	createdAt time.Time,
	updatedAt time.Time,
	createdBy sql.NullString,
) (*role.Role, error) {
	id, err := role.ParseID(roleID)
	if err != nil {
		return nil, fmt.Errorf("invalid role id: %w", err)
	}

	var tid *role.ID
	if tenantID.Valid {
		parsedTID, err := role.ParseID(tenantID.String)
		if err != nil {
			return nil, fmt.Errorf("invalid tenant id: %w", err)
		}
		tid = &parsedTID
	}

	var createdByID *role.ID
	if createdBy.Valid {
		parsedCB, err := role.ParseID(createdBy.String)
		if err != nil {
			return nil, fmt.Errorf("invalid created_by id: %w", err)
		}
		createdByID = &parsedCB
	}

	return role.Reconstruct(
		id,
		tid,
		slug,
		name,
		description.String,
		isSystem,
		hierarchyLevel,
		hasFullDataAccess,
		permissions,
		createdAt,
		updatedAt,
		createdByID,
	), nil
}

// Ensure RoleRepository implements role.Repository
var _ role.Repository = (*RoleRepository)(nil)
