package component

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// Repository defines the interface for component persistence.
type Repository interface {
	// Global Component Operations
	Upsert(ctx context.Context, comp *Component) (shared.ID, error)
	GetByPURL(ctx context.Context, purl string) (*Component, error)
	GetByID(ctx context.Context, id shared.ID) (*Component, error)

	// License Operations
	// LinkLicenses links licenses to a component and returns the count of newly linked licenses.
	LinkLicenses(ctx context.Context, componentID shared.ID, licenses []string) (linked int, err error)

	// Asset Dependency Operations (Links)
	LinkAsset(ctx context.Context, dep *AssetDependency) error
	GetDependency(ctx context.Context, id shared.ID) (*AssetDependency, error)
	UpdateDependency(ctx context.Context, dep *AssetDependency) error
	DeleteDependency(ctx context.Context, id shared.ID) error
	DeleteByAssetID(ctx context.Context, assetID shared.ID) error

	// GetExistingDependencyByPURL retrieves an existing asset_component by asset and component PURL.
	// Used for parent lookup during rescan when parent component exists from previous scan.
	// Returns nil, nil if not found.
	GetExistingDependencyByPURL(ctx context.Context, assetID shared.ID, purl string) (*AssetDependency, error)

	// GetExistingDependencyByComponentID retrieves an existing asset_component by asset, component, and path.
	// Used for duplicate detection during ingestion.
	// Returns nil, nil if not found.
	GetExistingDependencyByComponentID(ctx context.Context, assetID shared.ID, componentID shared.ID, path string) (*AssetDependency, error)

	// UpdateAssetDependencyParent updates the parent_component_id and depth of an asset_component.
	// Used in three-pass ingestion to set parent references after all components are inserted.
	UpdateAssetDependencyParent(ctx context.Context, id shared.ID, parentID shared.ID, depth int) error

	// ListComponents retrieves global components (optionally filtered by usage).
	ListComponents(ctx context.Context, filter Filter, page pagination.Pagination) (pagination.Result[*Component], error)

	// ListDependencies retrieves dependencies for an asset (joined with component details).
	ListDependencies(ctx context.Context, assetID shared.ID, page pagination.Pagination) (pagination.Result[*AssetDependency], error)

	// GetStats retrieves aggregated component statistics.
	GetStats(ctx context.Context, tenantID shared.ID) (*ComponentStats, error)

	// GetEcosystemStats retrieves per-ecosystem statistics.
	GetEcosystemStats(ctx context.Context, tenantID shared.ID) ([]EcosystemStats, error)

	// GetVulnerableComponents retrieves components with vulnerability details.
	GetVulnerableComponents(ctx context.Context, tenantID shared.ID, limit int) ([]VulnerableComponent, error)

	// GetLicenseStats retrieves license statistics for a tenant.
	GetLicenseStats(ctx context.Context, tenantID shared.ID) ([]LicenseStats, error)
}

// Filter defines criteria for filtering components.
type Filter struct {
	TenantID           *shared.ID // Filter components used by tenant
	AssetID            *shared.ID // Filter components used by asset
	Name               *string
	PURL               *string
	Ecosystems         []Ecosystem
	DependencyTypes    []DependencyType
	Statuses           []Status
	Licenses           []string
	HasVulnerabilities *bool
}

// NewFilter creates a new empty filter.
func NewFilter() Filter {
	return Filter{}
}

func (f Filter) WithTenantID(id shared.ID) Filter {
	f.TenantID = &id
	return f
}

func (f Filter) WithAssetID(id shared.ID) Filter {
	f.AssetID = &id
	return f
}

func (f Filter) WithName(name string) Filter {
	f.Name = &name
	return f
}

func (f Filter) WithEcosystems(ecosystems ...Ecosystem) Filter {
	f.Ecosystems = ecosystems
	return f
}

func (f Filter) WithStatuses(statuses ...Status) Filter {
	f.Statuses = statuses
	return f
}

func (f Filter) WithDependencyTypes(types ...DependencyType) Filter {
	f.DependencyTypes = types
	return f
}

func (f Filter) WithHasVulnerabilities(has bool) Filter {
	f.HasVulnerabilities = &has
	return f
}

func (f Filter) WithLicenses(licenses ...string) Filter {
	f.Licenses = licenses
	return f
}
