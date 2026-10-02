package app

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
)

// CreateTenantInput represents the input for creating a tenant.
type CreateTenantInput struct {
	Name        string `json:"name" validate:"required,min=1,max=255"`
	Slug        string `json:"slug" validate:"required,slug,min=3,max=63"`
	Description string `json:"description" validate:"max=1000"`
	OwnerID     string `json:"owner_id" validate:"required,uuid"`
}

// UpdateTenantInput represents the input for updating a tenant.
type UpdateTenantInput struct {
	ID          string  `json:"id" validate:"required,uuid"`
	Name        *string `json:"name,omitempty" validate:"omitempty,min=1,max=255"`
	Description *string `json:"description,omitempty" validate:"omitempty,max=1000"`
}

// ListTenantsFilter represents filters for listing tenants.
type ListTenantsFilter struct {
	Search    string   `json:"search"`
	Status    []string `json:"status"`
	Page      int      `json:"page"`
	PerPage   int      `json:"per_page"`
	SortBy    string   `json:"sort_by"`
	SortOrder string   `json:"sort_order"`
}

// AddMemberInput represents the input for adding a member to a tenant.
type AddMemberInput struct {
	TenantID string   `json:"tenant_id" validate:"required,uuid"`
	UserID   string   `json:"user_id" validate:"required,uuid"`
	RoleIDs  []string `json:"role_ids" validate:"dive,uuid"`
}

// TenantService defines the interface for tenant operations.
type TenantService interface {
	// Create creates a new tenant.
	Create(ctx context.Context, input CreateTenantInput) (*tenant.Tenant, error)

	// Get retrieves a tenant by ID.
	Get(ctx context.Context, tenantID shared.ID) (*tenant.Tenant, error)

	// GetBySlug retrieves a tenant by slug.
	GetBySlug(ctx context.Context, slug string) (*tenant.Tenant, error)

	// List returns paginated tenants matching the filter.
	List(ctx context.Context, filter ListTenantsFilter) (*ListResult[*tenant.Tenant], error)

	// Update updates an existing tenant.
	Update(ctx context.Context, input UpdateTenantInput) (*tenant.Tenant, error)

	// Delete soft-deletes a tenant.
	Delete(ctx context.Context, tenantID shared.ID) error

	// GetUserTenants returns all tenants a user belongs to.
	GetUserTenants(ctx context.Context, userID shared.ID) ([]*tenant.Tenant, error)
}

// TenantMemberService defines the interface for tenant member operations.
type TenantMemberService interface {
	// AddMember adds a user to a tenant.
	AddMember(ctx context.Context, input AddMemberInput) error

	// RemoveMember removes a user from a tenant.
	RemoveMember(ctx context.Context, tenantID, userID shared.ID) error

	// GetMembers returns all members of a tenant.
	GetMembers(ctx context.Context, tenantID shared.ID) ([]*tenant.Membership, error)

	// GetMember returns a specific member of a tenant.
	GetMember(ctx context.Context, tenantID, userID shared.ID) (*tenant.Membership, error)

	// UpdateMemberRoles updates a member's roles.
	UpdateMemberRoles(ctx context.Context, tenantID, userID shared.ID, roleIDs []shared.ID) error

	// IsMember checks if a user is a member of a tenant.
	IsMember(ctx context.Context, tenantID, userID shared.ID) (bool, error)
}
