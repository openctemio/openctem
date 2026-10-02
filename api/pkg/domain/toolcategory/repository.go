package toolcategory

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// Filter defines filter options for listing categories.
type Filter struct {
	TenantID  *shared.ID // Include tenant custom categories
	IsBuiltin *bool      // Filter by builtin status
	Search    string     // Search by name or display name
}

// Repository defines the interface for tool category persistence.
type Repository interface {
	// Create creates a new tool category.
	Create(ctx context.Context, category *ToolCategory) error

	// GetByID returns a category by ID.
	GetByID(ctx context.Context, id shared.ID) (*ToolCategory, error)

	// GetByName returns a category by name within a scope (tenant or platform).
	// If tenantID is nil, it looks for platform category.
	GetByName(ctx context.Context, tenantID *shared.ID, name string) (*ToolCategory, error)

	// List returns categories matching the filter with pagination.
	// Always includes platform (builtin) categories.
	// If filter.TenantID is set, also includes that tenant's custom categories.
	List(ctx context.Context, filter Filter, page pagination.Pagination) (pagination.Result[*ToolCategory], error)

	// ListAll returns all categories for a tenant context (platform + tenant custom).
	// This is a simpler method without pagination for dropdowns/selects.
	ListAll(ctx context.Context, tenantID *shared.ID) ([]*ToolCategory, error)

	// Update updates an existing category.
	Update(ctx context.Context, category *ToolCategory) error

	// Delete deletes a category by ID.
	// Only tenant custom categories can be deleted.
	Delete(ctx context.Context, id shared.ID) error

	// ExistsByName checks if a category with the given name exists in the scope.
	ExistsByName(ctx context.Context, tenantID *shared.ID, name string) (bool, error)

	// CountByTenant returns the number of custom categories for a tenant.
	CountByTenant(ctx context.Context, tenantID shared.ID) (int64, error)
}
