package role

import (
	"context"
)

// Repository defines the interface for role persistence operations.
type Repository interface {
	// === Role CRUD ===

	// Create creates a new role.
	Create(ctx context.Context, role *Role) error

	// GetByID retrieves a role by its ID.
	GetByID(ctx context.Context, id ID) (*Role, error)

	// GetBySlug retrieves a role by slug within a tenant or system.
	// For system roles, tenantID should be nil.
	GetBySlug(ctx context.Context, tenantID *ID, slug string) (*Role, error)

	// ListForTenant returns all roles available for a tenant.
	// Includes both system roles and tenant's custom roles.
	ListForTenant(ctx context.Context, tenantID ID) ([]*Role, error)

	// ListSystemRoles returns only system roles.
	ListSystemRoles(ctx context.Context) ([]*Role, error)

	// Update updates a role (only custom roles can be updated).
	Update(ctx context.Context, role *Role) error

	// Delete deletes a role (only custom roles can be deleted).
	Delete(ctx context.Context, id ID) error

	// === User-Role Assignments (Multiple Roles per User) ===

	// GetUserRoles returns all roles for a user in a tenant.
	GetUserRoles(ctx context.Context, tenantID, userID ID) ([]*Role, error)

	// GetUserPermissions returns all permissions for a user (UNION of all roles).
	GetUserPermissions(ctx context.Context, tenantID, userID ID) ([]string, error)

	// HasFullDataAccess checks if user has full data access (any role with has_full_data_access=true).
	HasFullDataAccess(ctx context.Context, tenantID, userID ID) (bool, error)

	// AssignRole assigns a role to a user (adds to user's roles).
	AssignRole(ctx context.Context, tenantID, userID, roleID ID, assignedBy *ID) error

	// RemoveRole removes a role from a user.
	RemoveRole(ctx context.Context, tenantID, userID, roleID ID) error

	// SetUserRoles replaces all roles for a user.
	SetUserRoles(ctx context.Context, tenantID, userID ID, roleIDs []ID, assignedBy *ID) error

	// BulkAssignRoleToUsers assigns a role to multiple users at once.
	BulkAssignRoleToUsers(ctx context.Context, tenantID, roleID ID, userIDs []ID, assignedBy *ID) error

	// === Role Members ===

	// ListRoleMembers returns all users who have a specific role in a tenant.
	ListRoleMembers(ctx context.Context, tenantID, roleID ID) ([]*UserRole, error)

	// CountUsersWithRole returns the count of users with a specific role.
	CountUsersWithRole(ctx context.Context, roleID ID) (int, error)
}

// PermissionRepository defines the interface for permission persistence operations.
type PermissionRepository interface {
	// ListModulesWithPermissions returns all modules with their permissions.
	ListModulesWithPermissions(ctx context.Context) ([]*Module, error)

	// ListPermissions returns all permissions.
	ListPermissions(ctx context.Context) ([]*Permission, error)

	// GetByID retrieves a permission by its ID.
	GetByID(ctx context.Context, id string) (*Permission, error)

	// Exists checks if a permission exists.
	Exists(ctx context.Context, id string) (bool, error)

	// ValidatePermissions validates multiple permissions.
	// Returns (valid, invalidIDs, error).
	ValidatePermissions(ctx context.Context, ids []string) (bool, []string, error)
}

// Module represents a feature grouping for permissions.
type Module struct {
	ID           string
	Name         string
	Description  string
	Icon         string
	DisplayOrder int
	IsActive     bool
	Permissions  []*Permission
}

// Permission represents a granular permission.
type Permission struct {
	ID          string // e.g., "assets:read"
	ModuleID    string
	Name        string
	Description string
	IsActive    bool
}
