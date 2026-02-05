package assettype

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// CategoryRepository defines the interface for category persistence.
type CategoryRepository interface {
	// Create persists a new category.
	Create(ctx context.Context, category *Category) error

	// GetByID retrieves a category by its ID.
	GetByID(ctx context.Context, id shared.ID) (*Category, error)

	// GetByCode retrieves a category by its code.
	GetByCode(ctx context.Context, code string) (*Category, error)

	// Update updates an existing category.
	Update(ctx context.Context, category *Category) error

	// Delete removes a category by its ID.
	Delete(ctx context.Context, id shared.ID) error

	// List retrieves categories with pagination.
	List(ctx context.Context, filter CategoryFilter, page pagination.Pagination) (pagination.Result[*Category], error)

	// ListActive retrieves all active categories.
	ListActive(ctx context.Context) ([]*Category, error)
}

// Repository defines the interface for asset type persistence.
// Asset types are read-only for regular users (system-level configuration).
type Repository interface {
	// GetByID retrieves an asset type by its ID.
	GetByID(ctx context.Context, id shared.ID) (*AssetType, error)

	// GetByCode retrieves an asset type by its code.
	GetByCode(ctx context.Context, code string) (*AssetType, error)

	// List retrieves asset types with filtering and pagination.
	List(ctx context.Context, filter Filter, opts ListOptions, page pagination.Pagination) (pagination.Result[*AssetType], error)

	// ListWithCategory retrieves asset types with their categories.
	ListWithCategory(ctx context.Context, filter Filter, opts ListOptions, page pagination.Pagination) (pagination.Result[*AssetTypeWithCategory], error)

	// ListActive retrieves all active asset types.
	ListActive(ctx context.Context) ([]*AssetType, error)

	// ListActiveByCategory retrieves active asset types by category.
	ListActiveByCategory(ctx context.Context, categoryID shared.ID) ([]*AssetType, error)

	// ExistsByCode checks if an asset type with the given code exists.
	ExistsByCode(ctx context.Context, code string) (bool, error)
}

// CategoryFilter defines the filtering options for listing categories.
type CategoryFilter struct {
	Code     *string // Filter by code
	Name     *string // Filter by name (partial match)
	IsActive *bool   // Filter by active status
	Search   *string // Full-text search
}

// NewCategoryFilter creates an empty category filter.
func NewCategoryFilter() CategoryFilter {
	return CategoryFilter{}
}

// WithCode adds a code filter.
func (f CategoryFilter) WithCode(code string) CategoryFilter {
	f.Code = &code
	return f
}

// WithName adds a name filter.
func (f CategoryFilter) WithName(name string) CategoryFilter {
	f.Name = &name
	return f
}

// WithIsActive adds an active status filter.
func (f CategoryFilter) WithIsActive(isActive bool) CategoryFilter {
	f.IsActive = &isActive
	return f
}

// WithSearch adds a search filter.
func (f CategoryFilter) WithSearch(search string) CategoryFilter {
	f.Search = &search
	return f
}

// Filter defines the filtering options for listing asset types.
type Filter struct {
	CategoryID       *string  // Filter by category ID
	Code             *string  // Filter by code
	Name             *string  // Filter by name (partial match)
	IsActive         *bool    // Filter by active status
	IsSystem         *bool    // Filter by system type
	IsDiscoverable   *bool    // Filter by discoverable
	IsScannable      *bool    // Filter by scannable
	SupportsWildcard *bool    // Filter by wildcard support
	SupportsCIDR     *bool    // Filter by CIDR support
	Search           *string  // Full-text search
	Codes            []string // Filter by multiple codes
}

// NewFilter creates an empty filter.
func NewFilter() Filter {
	return Filter{}
}

// WithCategoryID adds a category ID filter.
func (f Filter) WithCategoryID(categoryID string) Filter {
	f.CategoryID = &categoryID
	return f
}

// WithCode adds a code filter.
func (f Filter) WithCode(code string) Filter {
	f.Code = &code
	return f
}

// WithCodes adds multiple codes filter.
func (f Filter) WithCodes(codes ...string) Filter {
	f.Codes = codes
	return f
}

// WithName adds a name filter.
func (f Filter) WithName(name string) Filter {
	f.Name = &name
	return f
}

// WithIsActive adds an active status filter.
func (f Filter) WithIsActive(isActive bool) Filter {
	f.IsActive = &isActive
	return f
}

// WithIsSystem adds a system type filter.
func (f Filter) WithIsSystem(isSystem bool) Filter {
	f.IsSystem = &isSystem
	return f
}

// WithIsDiscoverable adds a discoverable filter.
func (f Filter) WithIsDiscoverable(discoverable bool) Filter {
	f.IsDiscoverable = &discoverable
	return f
}

// WithIsScannable adds a scannable filter.
func (f Filter) WithIsScannable(scannable bool) Filter {
	f.IsScannable = &scannable
	return f
}

// WithSupportsWildcard adds a wildcard support filter.
func (f Filter) WithSupportsWildcard(supports bool) Filter {
	f.SupportsWildcard = &supports
	return f
}

// WithSupportsCIDR adds a CIDR support filter.
func (f Filter) WithSupportsCIDR(supports bool) Filter {
	f.SupportsCIDR = &supports
	return f
}

// WithSearch adds a search filter.
func (f Filter) WithSearch(search string) Filter {
	f.Search = &search
	return f
}

// ListOptions contains options for listing asset types.
type ListOptions struct {
	Sort *pagination.SortOption
}

// NewListOptions creates empty list options.
func NewListOptions() ListOptions {
	return ListOptions{}
}

// WithSort adds sorting options.
func (o ListOptions) WithSort(sort *pagination.SortOption) ListOptions {
	o.Sort = sort
	return o
}

// AllowedSortFields returns the allowed sort fields for asset types.
func AllowedSortFields() map[string]string {
	return map[string]string{
		"code":          "code",
		"name":          "name",
		"display_order": "display_order",
		"created_at":    "created_at",
		"updated_at":    "updated_at",
	}
}

// CategoryAllowedSortFields returns the allowed sort fields for categories.
func CategoryAllowedSortFields() map[string]string {
	return map[string]string{
		"code":          "code",
		"name":          "name",
		"display_order": "display_order",
		"created_at":    "created_at",
		"updated_at":    "updated_at",
	}
}
