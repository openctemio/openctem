package app

import (
	"context"

	"github.com/openctemio/api/pkg/domain/role"
	"github.com/openctemio/api/pkg/domain/shared"
)

// CreateRoleInput represents the input for creating a role.
type CreateRoleInput struct {
	TenantID    *string  `json:"tenant_id,omitempty" validate:"omitempty,uuid"`
	Name        string   `json:"name" validate:"required,min=1,max=100"`
	Slug        string   `json:"slug" validate:"required,slug,min=2,max=50"`
	Description string   `json:"description" validate:"max=500"`
	Permissions []string `json:"permissions" validate:"required,min=1,dive,permission"`
}

// UpdateRoleInput represents the input for updating a role.
type UpdateRoleInput struct {
	TenantID    *string   `json:"tenant_id,omitempty" validate:"omitempty,uuid"`
	ID          string    `json:"id" validate:"required,uuid"`
	Name        *string   `json:"name,omitempty" validate:"omitempty,min=1,max=100"`
	Description *string   `json:"description,omitempty" validate:"omitempty,max=500"`
	Permissions *[]string `json:"permissions,omitempty" validate:"omitempty,min=1,dive,permission"`
}

// ListRolesFilter represents filters for listing roles.
type ListRolesFilter struct {
	TenantID       *string `json:"tenant_id"`
	Search         string  `json:"search"`
	IncludeSystem  bool    `json:"include_system"`
	IncludeDefault bool    `json:"include_default"`
	Page           int     `json:"page"`
	PerPage        int     `json:"per_page"`
	SortBy         string  `json:"sort_by"`
	SortOrder      string  `json:"sort_order"`
}

// RoleService defines the interface for role operations.
// OSS includes predefined roles; Enterprise adds custom role creation.
type RoleService interface {
	// Create creates a new role (Enterprise only).
	// OSS edition returns ErrNotSupported.
	Create(ctx context.Context, input CreateRoleInput) (*role.Role, error)

	// Get retrieves a role by ID.
	Get(ctx context.Context, tenantID *shared.ID, roleID shared.ID) (*role.Role, error)

	// GetBySlug retrieves a role by slug.
	GetBySlug(ctx context.Context, tenantID *shared.ID, slug string) (*role.Role, error)

	// List returns roles matching the filter.
	List(ctx context.Context, filter ListRolesFilter) (*ListResult[*role.Role], error)

	// Update updates an existing role (Enterprise only for custom roles).
	// System roles cannot be modified.
	Update(ctx context.Context, input UpdateRoleInput) (*role.Role, error)

	// Delete deletes a role (Enterprise only for custom roles).
	// System roles cannot be deleted.
	Delete(ctx context.Context, tenantID *shared.ID, roleID shared.ID) error

	// GetPredefinedRoles returns the predefined system roles.
	GetPredefinedRoles(ctx context.Context) ([]*role.Role, error)

	// AssignToUser assigns a role to a user.
	AssignToUser(ctx context.Context, tenantID, userID, roleID shared.ID) error

	// RemoveFromUser removes a role from a user.
	RemoveFromUser(ctx context.Context, tenantID, userID, roleID shared.ID) error

	// GetUserRoles returns all roles assigned to a user.
	GetUserRoles(ctx context.Context, tenantID, userID shared.ID) ([]*role.Role, error)

	// GetUserPermissions returns all permissions for a user (aggregated from roles).
	GetUserPermissions(ctx context.Context, tenantID, userID shared.ID) ([]string, error)

	// HasPermission checks if a user has a specific permission.
	HasPermission(ctx context.Context, tenantID, userID shared.ID, permission string) (bool, error)
}
