package datasource

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// =============================================================================
// DataSource Repository
// =============================================================================

// Filter defines the filter options for listing data sources.
type Filter struct {
	TenantID     string         // Filter by tenant ID
	Type         SourceType     // Filter by source type
	Types        []SourceType   // Filter by multiple source types
	Status       SourceStatus   // Filter by status
	Statuses     []SourceStatus // Filter by multiple statuses
	Search       string         // Search in name and description
	Capabilities []Capability   // Filter by capabilities
}

// ListOptions defines options for listing data sources.
type ListOptions struct {
	Page      int
	PerPage   int
	SortBy    string // name, type, status, created_at, updated_at, last_seen_at
	SortOrder string // asc, desc
}

// ListResult represents a paginated list result.
type ListResult struct {
	Data       []*DataSource
	Total      int64
	Page       int
	PerPage    int
	TotalPages int
}

// Repository defines the interface for data source persistence.
type Repository interface {
	// Create creates a new data source.
	Create(ctx context.Context, ds *DataSource) error

	// GetByID retrieves a data source by ID.
	GetByID(ctx context.Context, id shared.ID) (*DataSource, error)

	// GetByTenantAndName retrieves a data source by tenant ID and name.
	GetByTenantAndName(ctx context.Context, tenantID shared.ID, name string) (*DataSource, error)

	// GetByAPIKeyPrefix retrieves a data source by API key prefix.
	// Used for quick lookup during authentication.
	GetByAPIKeyPrefix(ctx context.Context, prefix string) (*DataSource, error)

	// Update updates an existing data source.
	Update(ctx context.Context, ds *DataSource) error

	// Delete deletes a data source by ID.
	Delete(ctx context.Context, id shared.ID) error

	// List lists data sources with filtering and pagination.
	List(ctx context.Context, filter Filter, opts ListOptions) (ListResult, error)

	// Count returns the total number of data sources matching the filter.
	Count(ctx context.Context, filter Filter) (int64, error)

	// MarkStaleAsInactive marks data sources that haven't been seen recently as inactive.
	// Returns the number of sources marked as inactive.
	MarkStaleAsInactive(ctx context.Context, tenantID shared.ID, staleThresholdMinutes int) (int, error)

	// GetActiveByTenant retrieves all active data sources for a tenant.
	GetActiveByTenant(ctx context.Context, tenantID shared.ID) ([]*DataSource, error)
}
