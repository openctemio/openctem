package asset

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// Repository defines the interface for asset persistence.
// Alias: Store (preferred for new code)
// Security: All methods that access tenant-scoped data require tenantID parameter.
type Repository interface {
	// Create persists a new asset.
	Create(ctx context.Context, asset *Asset) error

	// GetByID retrieves an asset by its ID within a tenant.
	// Security: Requires tenantID to prevent cross-tenant data access.
	GetByID(ctx context.Context, tenantID, id shared.ID) (*Asset, error)

	// Update updates an existing asset.
	// Security: Asset's TenantID is validated internally.
	Update(ctx context.Context, asset *Asset) error

	// Delete removes an asset by its ID within a tenant.
	// Security: Requires tenantID to prevent cross-tenant deletion.
	Delete(ctx context.Context, tenantID, id shared.ID) error

	// List retrieves assets with filtering, sorting, and pagination.
	List(ctx context.Context, filter Filter, opts ListOptions, page pagination.Pagination) (pagination.Result[*Asset], error)

	// Count returns the total number of assets matching the filter.
	Count(ctx context.Context, filter Filter) (int64, error)

	// ExistsByName checks if an asset with the given name exists within a tenant.
	// Security: Requires tenantID to prevent cross-tenant enumeration.
	ExistsByName(ctx context.Context, tenantID shared.ID, name string) (bool, error)

	// GetByExternalID retrieves an asset by external ID and provider.
	GetByExternalID(ctx context.Context, tenantID shared.ID, provider Provider, externalID string) (*Asset, error)

	// GetByName retrieves an asset by name within a tenant.
	GetByName(ctx context.Context, tenantID shared.ID, name string) (*Asset, error)

	// FindRepositoryByRepoName finds a repository asset whose name ends with the given repo name.
	// This is useful for matching agent-created assets (e.g., "github.com-org/repo") with SCM imports (e.g., "repo").
	FindRepositoryByRepoName(ctx context.Context, tenantID shared.ID, repoName string) (*Asset, error)

	// FindRepositoryByFullName finds a repository asset that matches the given full name (org/repo format).
	// It searches for assets whose name or external_id contains the full name pattern.
	FindRepositoryByFullName(ctx context.Context, tenantID shared.ID, fullName string) (*Asset, error)

	// ==========================================================================
	// Batch Operations (for high-performance ingestion)
	// ==========================================================================

	// GetByNames retrieves multiple assets by their names within a tenant.
	// Returns a map of name -> Asset for found assets.
	GetByNames(ctx context.Context, tenantID shared.ID, names []string) (map[string]*Asset, error)

	// UpsertBatch creates or updates multiple assets in a single operation.
	// Uses PostgreSQL ON CONFLICT for atomic upsert behavior.
	// Returns the number of created and updated assets.
	UpsertBatch(ctx context.Context, assets []*Asset) (created int, updated int, err error)

	// UpdateFindingCounts updates finding counts for multiple assets in batch.
	// This is used after bulk finding ingestion to refresh asset statistics.
	UpdateFindingCounts(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) error
}

// RepositoryExtensionRepository defines the interface for repository extension persistence.
type RepositoryExtensionRepository interface {
	// Create persists a new repository extension.
	Create(ctx context.Context, repo *RepositoryExtension) error

	// GetByAssetID retrieves a repository extension by asset ID.
	GetByAssetID(ctx context.Context, assetID shared.ID) (*RepositoryExtension, error)

	// Update updates an existing repository extension.
	Update(ctx context.Context, repo *RepositoryExtension) error

	// Delete removes a repository extension by asset ID.
	Delete(ctx context.Context, assetID shared.ID) error

	// GetByFullName retrieves a repository by full name.
	GetByFullName(ctx context.Context, tenantID shared.ID, fullName string) (*RepositoryExtension, error)

	// ListByTenant retrieves all repositories for a tenant.
	ListByTenant(ctx context.Context, tenantID shared.ID, opts ListOptions, page pagination.Pagination) (pagination.Result[*RepositoryExtension], error)
}

// Filter defines the filtering options for listing assets.
type Filter struct {
	TenantID      *string       // Filter by tenant ID
	Name          *string       // Filter by name (partial match)
	Types         []AssetType   // Filter by asset types
	Criticalities []Criticality // Filter by criticality levels
	Statuses      []Status      // Filter by statuses
	Scopes        []Scope       // Filter by scopes
	Exposures     []Exposure    // Filter by exposure levels
	Providers     []Provider    // Filter by providers
	SyncStatuses  []SyncStatus  // Filter by sync statuses
	Tags          []string      // Filter by tags
	Search        *string       // Full-text search across name and description
	MinRiskScore  *int          // Filter by minimum risk score
	MaxRiskScore  *int          // Filter by maximum risk score
	HasFindings   *bool         // Filter by whether asset has findings
	ParentID      *string       // Filter by parent asset ID
}

// ListOptions contains options for listing assets (sorting).
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

// AllowedSortFields returns the allowed sort fields for assets.
func AllowedSortFields() map[string]string {
	return map[string]string{
		"name":          "name",
		"created_at":    "created_at",
		"updated_at":    "updated_at",
		"criticality":   "criticality",
		"status":        "status",
		"type":          "asset_type",
		"scope":         "scope",
		"exposure":      "exposure",
		"risk_score":    "risk_score",
		"finding_count": "finding_count",
		"first_seen":    "first_seen",
		"last_seen":     "last_seen",
		"provider":      "provider",
		"sync_status":   "sync_status",
		"last_synced":   "last_synced_at",
	}
}

// NewFilter creates an empty filter.
func NewFilter() Filter {
	return Filter{}
}

// WithName adds a name filter.
func (f Filter) WithName(name string) Filter {
	f.Name = &name
	return f
}

// WithTypes adds a types filter.
func (f Filter) WithTypes(types ...AssetType) Filter {
	f.Types = types
	return f
}

// WithCriticalities adds a criticalities filter.
func (f Filter) WithCriticalities(criticalities ...Criticality) Filter {
	f.Criticalities = criticalities
	return f
}

// WithStatuses adds a statuses filter.
func (f Filter) WithStatuses(statuses ...Status) Filter {
	f.Statuses = statuses
	return f
}

// WithTags adds a tags filter.
func (f Filter) WithTags(tags ...string) Filter {
	f.Tags = tags
	return f
}

// WithSearch adds a full-text search filter.
func (f Filter) WithSearch(search string) Filter {
	f.Search = &search
	return f
}

// WithTenantID adds a tenant ID filter.
func (f Filter) WithTenantID(tenantID string) Filter {
	f.TenantID = &tenantID
	return f
}

// WithScopes adds a scopes filter.
func (f Filter) WithScopes(scopes ...Scope) Filter {
	f.Scopes = scopes
	return f
}

// WithExposures adds an exposures filter.
func (f Filter) WithExposures(exposures ...Exposure) Filter {
	f.Exposures = exposures
	return f
}

// WithMinRiskScore adds a minimum risk score filter.
func (f Filter) WithMinRiskScore(score int) Filter {
	f.MinRiskScore = &score
	return f
}

// WithMaxRiskScore adds a maximum risk score filter.
func (f Filter) WithMaxRiskScore(score int) Filter {
	f.MaxRiskScore = &score
	return f
}

// WithHasFindings adds a has findings filter.
func (f Filter) WithHasFindings(hasFindings bool) Filter {
	f.HasFindings = &hasFindings
	return f
}

// WithProviders adds a providers filter.
func (f Filter) WithProviders(providers ...Provider) Filter {
	f.Providers = providers
	return f
}

// WithSyncStatuses adds a sync statuses filter.
func (f Filter) WithSyncStatuses(statuses ...SyncStatus) Filter {
	f.SyncStatuses = statuses
	return f
}

// WithParentID adds a parent ID filter.
func (f Filter) WithParentID(parentID string) Filter {
	f.ParentID = &parentID
	return f
}

// IsEmpty returns true if no filters are set.
func (f Filter) IsEmpty() bool {
	return f.TenantID == nil &&
		f.Name == nil &&
		len(f.Types) == 0 &&
		len(f.Criticalities) == 0 &&
		len(f.Statuses) == 0 &&
		len(f.Scopes) == 0 &&
		len(f.Exposures) == 0 &&
		len(f.Providers) == 0 &&
		len(f.SyncStatuses) == 0 &&
		len(f.Tags) == 0 &&
		f.Search == nil &&
		f.MinRiskScore == nil &&
		f.MaxRiskScore == nil &&
		f.HasFindings == nil &&
		f.ParentID == nil
}
