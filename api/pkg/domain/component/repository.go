package component

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Graph and path bounds.
const (
	MaxGraphDepth = 10
	MaxGraphNodes = 500
	MaxPaths      = 20
)

// Sort keys of the package list ("-" prefix: descending).
var SortKeys = map[string]bool{
	"name": true, "assets": true, "versions": true, "risk": true, "vulns": true, "last_seen": true,
}

// Filter selects packages. Every query is limited to TenantID and, when
// Scope is set, to links of assets in the caller's data scope.
type Filter struct {
	TenantID     shared.ID
	Scope        *shared.DataScope
	Query        string
	PURLTypes    []string
	Licenses     []string
	Severities   []string
	KEV          *bool
	HasFix       *bool
	HasVulns     *bool
	Relationship []string
	Scopes       []string
	AssetID      *shared.ID
	OwnerID      *shared.ID
	Sort         string
}

// UsageFilter narrows where-used rows of one package.
type UsageFilter struct {
	VersionID    *shared.ID
	Relationship []string
	Scopes       []string
}

// Repository reads the inventory. Writes go through software.PackageWriter.
type Repository interface {
	ListPackages(ctx context.Context, f Filter, page pagination.Pagination) (pagination.Result[Package], error)
	PackageFacets(ctx context.Context, f Filter) (Facets, error)
	Summary(ctx context.Context, f Filter) (Summary, error)
	// GetPackage returns shared.ErrNotFound unless the package has a link in
	// the caller's scope.
	GetPackage(ctx context.Context, tenantID, productID shared.ID, scope *shared.DataScope) (*PackageDetail, error)
	ListVersions(ctx context.Context, tenantID, productID shared.ID, scope *shared.DataScope) ([]Version, error)
	ListUsages(ctx context.Context, tenantID, productID shared.ID, f UsageFilter, scope *shared.DataScope,
		page pagination.Pagination) (pagination.Result[Usage], error)
	ListVulnerabilities(ctx context.Context, tenantID, productID shared.ID, includeResolved bool,
		scope *shared.DataScope, page pagination.Pagination) (pagination.Result[Vulnerability], error)
	// ListAssetPackages lists one asset's package links (the caller checks
	// the asset is in scope).
	ListAssetPackages(ctx context.Context, tenantID, assetID shared.ID, page pagination.Pagination) (pagination.Result[Usage], error)
	DependencyPaths(ctx context.Context, tenantID, assetID, versionID shared.ID, limit int) ([]Path, error)
	DependencyGraph(ctx context.Context, tenantID, assetID shared.ID, focus *shared.ID, depth, limit int) (*Graph, error)
	ListSBOMEntries(ctx context.Context, tenantID shared.ID, assetID *shared.ID, scope *shared.DataScope, limit int) ([]SBOMEntry, error)
	// GetFindingComponent returns the version a finding names (global or
	// the tenant's own) and, when assetID is set, how that asset uses it.
	GetFindingComponent(ctx context.Context, tenantID, versionID shared.ID, assetID *shared.ID) (*FindingComponent, error)
}
