package permissionset

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Repository defines the interface for permission set persistence.
type Repository interface {
	// Permission Set CRUD
	Create(ctx context.Context, ps *PermissionSet) error
	GetByID(ctx context.Context, id shared.ID) (*PermissionSet, error)
	GetBySlug(ctx context.Context, tenantID *shared.ID, slug string) (*PermissionSet, error)
	Update(ctx context.Context, ps *PermissionSet) error
	Delete(ctx context.Context, id shared.ID) error

	// Permission Set queries
	List(ctx context.Context, filter ListFilter) ([]*PermissionSet, error)
	Count(ctx context.Context, filter ListFilter) (int64, error)
	ExistsBySlug(ctx context.Context, tenantID *shared.ID, slug string) (bool, error)
	ListByIDs(ctx context.Context, ids []shared.ID) ([]*PermissionSet, error)
	ListSystemSets(ctx context.Context) ([]*PermissionSet, error)
	ListByTenant(ctx context.Context, tenantID shared.ID, includeSystem bool) ([]*PermissionSet, error)

	// Permission Set Items
	AddItem(ctx context.Context, item *Item) error
	RemoveItem(ctx context.Context, permissionSetID shared.ID, permissionID string) error
	ListItems(ctx context.Context, permissionSetID shared.ID) ([]*Item, error)
	GetWithItems(ctx context.Context, id shared.ID) (*PermissionSetWithItems, error)
	BatchAddItems(ctx context.Context, items []*Item) error
	ReplaceItems(ctx context.Context, permissionSetID shared.ID, items []*Item) error

	// Version tracking
	CreateVersion(ctx context.Context, version *Version) error
	GetLatestVersion(ctx context.Context, permissionSetID shared.ID) (*Version, error)
	ListVersions(ctx context.Context, permissionSetID shared.ID) ([]*Version, error)

	// Inheritance queries
	GetParent(ctx context.Context, permissionSetID shared.ID) (*PermissionSet, error)
	ListChildren(ctx context.Context, parentSetID shared.ID) ([]*PermissionSet, error)
	GetInheritanceChain(ctx context.Context, permissionSetID shared.ID) ([]*PermissionSet, error)

	// Usage queries (for deletion checks)
	CountGroupsUsing(ctx context.Context, permissionSetID shared.ID) (int64, error)
	ListGroupIDsUsing(ctx context.Context, permissionSetID shared.ID) ([]shared.ID, error)
}

// ListFilter contains filter options for listing permission sets.
type ListFilter struct {
	// Tenant filter
	TenantID      *shared.ID // nil = system only, non-nil = tenant + system
	IncludeSystem bool       // Include system templates when filtering by tenant

	// Type filters
	SetTypes []SetType

	// Search
	Search string // Search in name, slug, description

	// Status filter
	IsActive *bool

	// Parent filter
	ParentSetID *shared.ID

	// Pagination
	Limit  int
	Offset int

	// Sorting
	OrderBy   string // "name", "created_at", "updated_at"
	OrderDesc bool
}

// DefaultListFilter returns a default filter.
func DefaultListFilter() ListFilter {
	return ListFilter{
		IncludeSystem: true,
		Limit:         50,
		Offset:        0,
		OrderBy:       "name",
	}
}

// SystemOnlyFilter returns a filter for system permission sets only.
func SystemOnlyFilter() ListFilter {
	return ListFilter{
		TenantID:      nil,
		IncludeSystem: false,
		SetTypes:      []SetType{SetTypeSystem},
		Limit:         100,
		OrderBy:       "name",
	}
}
