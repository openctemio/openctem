package findingsource

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

// Repository defines the interface for finding source persistence.
// Finding sources are read-only for regular users (system-level configuration).
type Repository interface {
	// GetByID retrieves a finding source by its ID.
	GetByID(ctx context.Context, id shared.ID) (*FindingSource, error)

	// GetByCode retrieves a finding source by its code.
	GetByCode(ctx context.Context, code string) (*FindingSource, error)

	// List retrieves finding sources with filtering and pagination.
	List(ctx context.Context, filter Filter, opts ListOptions, page pagination.Pagination) (pagination.Result[*FindingSource], error)

	// ListWithCategory retrieves finding sources with their categories.
	ListWithCategory(ctx context.Context, filter Filter, opts ListOptions, page pagination.Pagination) (pagination.Result[*FindingSourceWithCategory], error)

	// ListActive retrieves all active finding sources.
	ListActive(ctx context.Context) ([]*FindingSource, error)

	// ListActiveWithCategory retrieves all active finding sources with their categories.
	ListActiveWithCategory(ctx context.Context) ([]*FindingSourceWithCategory, error)

	// ListActiveByCategory retrieves active finding sources by category.
	ListActiveByCategory(ctx context.Context, categoryID shared.ID) ([]*FindingSource, error)

	// ExistsByCode checks if a finding source with the given code exists.
	ExistsByCode(ctx context.Context, code string) (bool, error)

	// IsValidCode checks if the code is a valid active finding source.
	IsValidCode(ctx context.Context, code string) (bool, error)
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

// Filter defines the filtering options for listing finding sources.
type Filter struct {
	CategoryID   *string  // Filter by category ID
	CategoryCode *string  // Filter by category code
	Code         *string  // Filter by code
	Name         *string  // Filter by name (partial match)
	IsActive     *bool    // Filter by active status
	IsSystem     *bool    // Filter by system type
	Search       *string  // Full-text search
	Codes        []string // Filter by multiple codes
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

// WithCategoryCode adds a category code filter.
func (f Filter) WithCategoryCode(categoryCode string) Filter {
	f.CategoryCode = &categoryCode
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

// WithSearch adds a search filter.
func (f Filter) WithSearch(search string) Filter {
	f.Search = &search
	return f
}

// ListOptions contains options for listing finding sources.
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

// AllowedSortFields returns the allowed sort fields for finding sources.
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
