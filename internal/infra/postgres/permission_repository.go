package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/openctemio/api/pkg/domain/role"
	"github.com/lib/pq"
)

// PermissionRepository implements role.PermissionRepository using PostgreSQL.
type PermissionRepository struct {
	db *DB
}

// NewPermissionRepository creates a new PermissionRepository.
func NewPermissionRepository(db *DB) *PermissionRepository {
	return &PermissionRepository{db: db}
}

// ListModulesWithPermissions returns all modules with their permissions.
func (r *PermissionRepository) ListModulesWithPermissions(ctx context.Context) ([]*role.Module, error) {
	// First get all modules
	moduleQuery := `
		SELECT id, name, description, icon, display_order, is_active
		FROM modules
		WHERE is_active = TRUE
		ORDER BY display_order ASC
	`

	moduleRows, err := r.db.QueryContext(ctx, moduleQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to list modules: %w", err)
	}
	defer moduleRows.Close()

	moduleMap := make(map[string]*role.Module)
	var modules []*role.Module

	for moduleRows.Next() {
		var m role.Module
		var description, icon sql.NullString

		if err := moduleRows.Scan(&m.ID, &m.Name, &description, &icon, &m.DisplayOrder, &m.IsActive); err != nil {
			return nil, fmt.Errorf("failed to scan module: %w", err)
		}

		m.Description = description.String
		m.Icon = icon.String
		m.Permissions = []*role.Permission{}

		moduleMap[m.ID] = &m
		modules = append(modules, &m)
	}

	if err := moduleRows.Err(); err != nil {
		return nil, err
	}

	// Then get all permissions
	permQuery := `
		SELECT id, module_id, name, description, is_active
		FROM permissions
		WHERE is_active = TRUE
		ORDER BY id ASC
	`

	permRows, err := r.db.QueryContext(ctx, permQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to list permissions: %w", err)
	}
	defer permRows.Close()

	for permRows.Next() {
		var p role.Permission
		var moduleID sql.NullString
		var description sql.NullString

		if err := permRows.Scan(&p.ID, &moduleID, &p.Name, &description, &p.IsActive); err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}

		p.ModuleID = moduleID.String
		p.Description = description.String

		if moduleID.Valid {
			if mod, ok := moduleMap[moduleID.String]; ok {
				mod.Permissions = append(mod.Permissions, &p)
			}
		}
	}

	return modules, permRows.Err()
}

// ListPermissions returns all permissions.
func (r *PermissionRepository) ListPermissions(ctx context.Context) ([]*role.Permission, error) {
	query := `
		SELECT id, module_id, name, description, is_active
		FROM permissions
		WHERE is_active = TRUE
		ORDER BY module_id, id ASC
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list permissions: %w", err)
	}
	defer rows.Close()

	var permissions []*role.Permission
	for rows.Next() {
		var p role.Permission
		var moduleID, description sql.NullString

		if err := rows.Scan(&p.ID, &moduleID, &p.Name, &description, &p.IsActive); err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}

		p.ModuleID = moduleID.String
		p.Description = description.String
		permissions = append(permissions, &p)
	}

	return permissions, rows.Err()
}

// GetByID retrieves a permission by its ID.
func (r *PermissionRepository) GetByID(ctx context.Context, id string) (*role.Permission, error) {
	query := `
		SELECT id, module_id, name, description, is_active
		FROM permissions
		WHERE id = $1
	`

	var p role.Permission
	var moduleID, description sql.NullString

	err := r.db.QueryRowContext(ctx, query, id).Scan(&p.ID, &moduleID, &p.Name, &description, &p.IsActive)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, role.ErrInvalidPermission
		}
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}

	p.ModuleID = moduleID.String
	p.Description = description.String

	return &p, nil
}

// Exists checks if a permission exists.
func (r *PermissionRepository) Exists(ctx context.Context, id string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM permissions WHERE id = $1 AND is_active = TRUE)`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, id).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check permission: %w", err)
	}

	return exists, nil
}

// ValidatePermissions validates multiple permissions.
func (r *PermissionRepository) ValidatePermissions(ctx context.Context, ids []string) (bool, []string, error) {
	if len(ids) == 0 {
		return true, nil, nil
	}

	// Get all valid permissions
	query := `SELECT id FROM permissions WHERE id = ANY($1) AND is_active = TRUE`

	rows, err := r.db.QueryContext(ctx, query, pq.Array(ids))
	if err != nil {
		return false, nil, fmt.Errorf("failed to validate permissions: %w", err)
	}
	defer rows.Close()

	validSet := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return false, nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		validSet[id] = true
	}

	if err := rows.Err(); err != nil {
		return false, nil, err
	}

	// Find invalid IDs
	var invalidIDs []string
	for _, id := range ids {
		if !validSet[id] {
			invalidIDs = append(invalidIDs, id)
		}
	}

	return len(invalidIDs) == 0, invalidIDs, nil
}

// Ensure PermissionRepository implements role.PermissionRepository
var _ role.PermissionRepository = (*PermissionRepository)(nil)
