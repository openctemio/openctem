package component

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Repository defines the interface for component persistence.
type Repository interface {
	// Global Component Operations
	Upsert(ctx context.Context, comp *Component) (shared.ID, error)
	GetByPURL(ctx context.Context, purl string) (*Component, error)
	GetByID(ctx context.Context, id shared.ID) (*Component, error)

	// License Operations
	// EnsureLicenses validates license identifiers, makes sure each exists in
	// the license dictionary (an unknown one is added with category and risk
	// "unknown"; an existing entry is never changed) and returns the valid
	// ones. It does not attach licenses to anything: a tenant's licenses go on
	// its own asset dependency (AssetDependency.SetLicense).
	EnsureLicenses(ctx context.Context, licenses []string) ([]string, error)

	// Asset Dependency Operations (Links)
	LinkAsset(ctx context.Context, dep *AssetDependency) error
	// GetDependency, UpdateDependency (by dep.TenantID()) and DeleteDependency
	// only see the tenant's own rows; another tenant's id is not found.
	GetDependency(ctx context.Context, tenantID, id shared.ID) (*AssetDependency, error)
	UpdateDependency(ctx context.Context, dep *AssetDependency) error
	DeleteDependency(ctx context.Context, tenantID, id shared.ID) error
	DeleteByAssetID(ctx context.Context, assetID shared.ID) error

	// GetExistingDependencyByPURL retrieves an existing asset_component by asset and component PURL.
	// Used for parent lookup during rescan when parent component exists from previous scan.
	// Returns nil, nil if not found.
	GetExistingDependencyByPURL(ctx context.Context, assetID shared.ID, purl string) (*AssetDependency, error)

	// GetExistingDependencyByComponentID retrieves an existing asset_component by asset, component, and path.
	// Used for duplicate detection during ingestion.
	// Returns nil, nil if not found.
	GetExistingDependencyByComponentID(ctx context.Context, assetID shared.ID, componentID shared.ID, path string) (*AssetDependency, error)

	// GetAssetDependency returns how a tenant's asset uses a component: the
	// shallowest asset_components row (direct before transitive) for the
	// (tenant, asset, component) triple, with the component attached. Used to
	// show a finding's manifest file and dependency type. Returns nil, nil if
	// the asset does not list the component.
	GetAssetDependency(ctx context.Context, tenantID, assetID, componentID shared.ID) (*AssetDependency, error)

	// UpdateAssetDependencyParent updates the parent_component_id and depth of an asset_component.
	// Used in three-pass ingestion to set parent references after all components are inserted.
	UpdateAssetDependencyParent(ctx context.Context, tenantID, id shared.ID, parentID shared.ID, depth int) error

	// ListComponents retrieves global components (optionally filtered by usage).
	ListComponents(ctx context.Context, filter Filter, page pagination.Pagination) (pagination.Result[*Component], error)

	// ListDependencies retrieves dependencies for an asset (joined with component details).
	ListDependencies(ctx context.Context, assetID shared.ID, page pagination.Pagination) (pagination.Result[*AssetDependency], error)

	// GetStats retrieves aggregated component statistics.
	GetStats(ctx context.Context, tenantID shared.ID) (*ComponentStats, error)

	// GetEcosystemStats retrieves per-ecosystem statistics.
	GetEcosystemStats(ctx context.Context, tenantID shared.ID) ([]EcosystemStats, error)

	// GetVulnerableComponents retrieves paginated vulnerable components with severity breakdown.
	GetVulnerableComponents(ctx context.Context, tenantID shared.ID, page pagination.Pagination) (pagination.Result[VulnerableComponent], error)

	// GetLicenseStats retrieves license statistics for a tenant.
	GetLicenseStats(ctx context.Context, tenantID shared.ID) ([]LicenseStats, error)

	// ListAssetUsage retrieves the assets that use a given global component
	// (blast-radius reverse lookup). Joins asset_components × assets,
	// scoped to the tenant. Returns empty result when the component is not
	// used by any asset of this tenant.
	//
	// When atRiskOnly is true, only assets that have at least one open
	// finding (status in new/confirmed/in_progress) for this component are
	// returned. Default false → returns every asset using the component
	// regardless of vulnerability status (full SBOM view).
	//
	// scope limits the assets to the caller's data scope (nil: all).
	ListAssetUsage(
		ctx context.Context,
		tenantID shared.ID,
		componentID shared.ID,
		atRiskOnly bool,
		scope *shared.DataScope,
		page pagination.Pagination,
	) (pagination.Result[ComponentAssetUsage], error)

	// ListVulnerabilities returns the CVEs that affect a global component
	// within the given tenant. Aggregates findings GROUP BY vulnerability_id
	// so a CVE appearing on multiple assets returns one row with
	// affected_assets_count rolled up. When includeResolved is false, only
	// open-status findings (new/confirmed/in_progress) count toward the row
	// but the CVE is still included if at least one open finding exists.
	ListVulnerabilities(
		ctx context.Context,
		tenantID, componentID shared.ID,
		includeResolved bool,
		page pagination.Pagination,
	) (pagination.Result[ComponentVulnerability], error)
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
	// DataScope limits the components to those used by assets in the
	// caller's data scope. Nil means unrestricted.
	DataScope *shared.DataScope
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
