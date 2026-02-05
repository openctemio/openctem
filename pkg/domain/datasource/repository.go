package datasource

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
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

// =============================================================================
// AssetSource Repository
// =============================================================================

// AssetSourceFilter defines the filter options for listing asset sources.
type AssetSourceFilter struct {
	AssetID    shared.ID  // Filter by asset ID
	SourceID   shared.ID  // Filter by source ID
	SourceType SourceType // Filter by source type
	IsPrimary  *bool      // Filter by primary flag
}

// AssetSourceListOptions defines options for listing asset sources.
type AssetSourceListOptions struct {
	Page      int
	PerPage   int
	SortBy    string // first_seen_at, last_seen_at, confidence
	SortOrder string // asc, desc
}

// AssetSourceListResult represents a paginated list result.
type AssetSourceListResult struct {
	Data       []*AssetSource
	Total      int64
	Page       int
	PerPage    int
	TotalPages int
}

// AssetSourceRepository defines the interface for asset source persistence.
type AssetSourceRepository interface {
	// Create creates a new asset source record.
	Create(ctx context.Context, as *AssetSource) error

	// GetByID retrieves an asset source by ID.
	GetByID(ctx context.Context, id shared.ID) (*AssetSource, error)

	// GetByAssetAndSource retrieves an asset source by asset ID, source type, and source ID.
	GetByAssetAndSource(ctx context.Context, assetID shared.ID, sourceType SourceType, sourceID *shared.ID) (*AssetSource, error)

	// Update updates an existing asset source.
	Update(ctx context.Context, as *AssetSource) error

	// Upsert creates or updates an asset source.
	// If the asset source exists, it updates the last_seen_at, seen_count, and contributed_data.
	Upsert(ctx context.Context, as *AssetSource) error

	// Delete deletes an asset source by ID.
	Delete(ctx context.Context, id shared.ID) error

	// DeleteByAsset deletes all asset sources for an asset.
	DeleteByAsset(ctx context.Context, assetID shared.ID) error

	// DeleteBySource deletes all asset sources for a data source.
	DeleteBySource(ctx context.Context, sourceID shared.ID) error

	// List lists asset sources with filtering and pagination.
	List(ctx context.Context, filter AssetSourceFilter, opts AssetSourceListOptions) (AssetSourceListResult, error)

	// GetByAsset retrieves all sources for an asset.
	GetByAsset(ctx context.Context, assetID shared.ID) ([]*AssetSource, error)

	// GetPrimaryByAsset retrieves the primary source for an asset.
	GetPrimaryByAsset(ctx context.Context, assetID shared.ID) (*AssetSource, error)

	// SetPrimary sets a source as the primary source for an asset.
	// This will unset any existing primary source for the asset.
	SetPrimary(ctx context.Context, assetSourceID shared.ID) error

	// CountBySource returns the number of assets for a data source.
	CountBySource(ctx context.Context, sourceID shared.ID) (int64, error)
}

// =============================================================================
// FindingDataSource Repository
// =============================================================================

// FindingDataSourceFilter defines the filter options for listing finding data sources.
type FindingDataSourceFilter struct {
	FindingID  shared.ID  // Filter by finding ID
	SourceID   shared.ID  // Filter by source ID
	SourceType SourceType // Filter by source type
	IsPrimary  *bool      // Filter by primary flag
}

// FindingDataSourceListOptions defines options for listing finding data sources.
type FindingDataSourceListOptions struct {
	Page      int
	PerPage   int
	SortBy    string // first_seen_at, last_seen_at, confidence
	SortOrder string // asc, desc
}

// FindingDataSourceListResult represents a paginated list result.
type FindingDataSourceListResult struct {
	Data       []*FindingDataSource
	Total      int64
	Page       int
	PerPage    int
	TotalPages int
}

// FindingDataSourceRepository defines the interface for finding data source persistence.
type FindingDataSourceRepository interface {
	// Create creates a new finding data source record.
	Create(ctx context.Context, fs *FindingDataSource) error

	// GetByID retrieves a finding data source by ID.
	GetByID(ctx context.Context, id shared.ID) (*FindingDataSource, error)

	// GetByFindingAndSource retrieves a finding data source by finding ID, source type, and source ID.
	GetByFindingAndSource(ctx context.Context, findingID shared.ID, sourceType SourceType, sourceID *shared.ID) (*FindingDataSource, error)

	// Update updates an existing finding data source.
	Update(ctx context.Context, fs *FindingDataSource) error

	// Upsert creates or updates a finding data source.
	// If the finding data source exists, it updates the last_seen_at, seen_count, and contributed_data.
	Upsert(ctx context.Context, fs *FindingDataSource) error

	// Delete deletes a finding data source by ID.
	Delete(ctx context.Context, id shared.ID) error

	// DeleteByFinding deletes all data sources for a finding.
	DeleteByFinding(ctx context.Context, findingID shared.ID) error

	// DeleteBySource deletes all finding data sources for a data source.
	DeleteBySource(ctx context.Context, sourceID shared.ID) error

	// List lists finding data sources with filtering and pagination.
	List(ctx context.Context, filter FindingDataSourceFilter, opts FindingDataSourceListOptions) (FindingDataSourceListResult, error)

	// GetByFinding retrieves all data sources for a finding.
	GetByFinding(ctx context.Context, findingID shared.ID) ([]*FindingDataSource, error)

	// GetPrimaryByFinding retrieves the primary data source for a finding.
	GetPrimaryByFinding(ctx context.Context, findingID shared.ID) (*FindingDataSource, error)

	// SetPrimary sets a data source as the primary source for a finding.
	// This will unset any existing primary source for the finding.
	SetPrimary(ctx context.Context, findingDataSourceID shared.ID) error

	// CountBySource returns the number of findings for a data source.
	CountBySource(ctx context.Context, sourceID shared.ID) (int64, error)
}
