package assetgroup

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/asset"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Repository defines the interface for asset group persistence.
type Repository interface {
	// Create persists a new asset group.
	Create(ctx context.Context, group *AssetGroup) error

	// GetByID retrieves an asset group by its ID.
	GetByID(ctx context.Context, id shared.ID) (*AssetGroup, error)

	// GetByTenantAndID retrieves an asset group by tenant and ID (tenant-scoped).
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*AssetGroup, error)

	// Update updates an existing asset group.
	// Security: tenantID enforces tenant scoping in SQL — caller MUST pass
	// the requesting tenant so IDOR is impossible (an attacker cannot mutate
	// another tenant's group by guessing the UUID).
	Update(ctx context.Context, tenantID shared.ID, group *AssetGroup) error

	// Delete removes an asset group by its ID.
	// Security: tenantID enforces tenant scoping in SQL — same rationale as Update.
	Delete(ctx context.Context, tenantID, id shared.ID) error

	// List retrieves asset groups with filtering, sorting, and pagination.
	List(ctx context.Context, filter Filter, opts ListOptions, page pagination.Pagination) (pagination.Result[*AssetGroup], error)

	// Count returns the total number of asset groups matching the filter.
	Count(ctx context.Context, filter Filter) (int64, error)

	// ExistsByName checks if an asset group with the given name exists.
	ExistsByName(ctx context.Context, tenantID shared.ID, name string) (bool, error)

	// GetStats returns aggregated statistics for asset groups.
	// A non-nil scope counts only members in that data scope.
	GetStats(ctx context.Context, tenantID shared.ID, scope *shared.DataScope) (*Stats, error)

	// AddAssets adds assets to a group. Only assets of the group's own
	// tenant are written; it returns how many of assetIDs are such assets.
	AddAssets(ctx context.Context, groupID shared.ID, assetIDs []shared.ID) (int, error)

	// FilterTenantAssetIDs returns the subset of assetIDs that are assets of
	// tenantID.
	FilterTenantAssetIDs(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) ([]shared.ID, error)

	// RemoveAssets removes assets from a group.
	RemoveAssets(ctx context.Context, groupID shared.ID, assetIDs []shared.ID) error

	// GetGroupAssets returns assets belonging to a group. A non-nil scope
	// keeps only the assets in that data scope (nil = all members).
	GetGroupAssets(ctx context.Context, groupID shared.ID, page pagination.Pagination, scope *shared.DataScope) (pagination.Result[*GroupAsset], error)

	// ListScanMembers returns one page of the group's members for scan
	// dispatch: only members of the tenant, archived assets left out (and
	// counted), ordered by name, after the cursor in q.
	ListScanMembers(ctx context.Context, q ScanMemberQuery) (*ScanMemberPage, error)

	// GetGroupFindings returns findings for assets belonging to a group. A
	// non-nil scope keeps only findings whose asset is in that data scope.
	GetGroupFindings(ctx context.Context, groupID shared.ID, page pagination.Pagination, scope *shared.DataScope) (pagination.Result[*GroupFinding], error)

	// GetGroupIDsByAssetID returns IDs of groups containing a specific asset.
	GetGroupIDsByAssetID(ctx context.Context, assetID shared.ID) ([]shared.ID, error)

	// RecalculateCounts recalculates asset counts for a group.
	RecalculateCounts(ctx context.Context, groupID shared.ID) error

	// GetDistinctAssetTypes returns all unique asset types in a group.
	// Used for scan compatibility checking.
	GetDistinctAssetTypes(ctx context.Context, groupID shared.ID) ([]string, error)

	// GetDistinctAssetTypesMultiple returns all unique asset types across multiple groups.
	// Used when scan has multiple asset groups (AssetGroupIDs[]).
	GetDistinctAssetTypesMultiple(ctx context.Context, groupIDs []shared.ID) ([]string, error)

	// CountAssetsByType returns the count of assets per stored
	// (type, sub_type) pair in a group.
	// Used for compatibility preview at scan creation.
	CountAssetsByType(ctx context.Context, groupID shared.ID) (map[asset.TypeRef]int64, error)
}

// Filter defines the filtering options for listing asset groups.
type Filter struct {
	TenantID      *string
	Search        *string
	Environments  []Environment
	Criticalities []Criticality
	BusinessUnit  *string
	// BusinessUnitID filters by the reconciled business_units FK (migration
	// 000211). Additive to BusinessUnit: callers may filter by the exact BU
	// record instead of the free-text label.
	BusinessUnitID *string
	Owner          *string
	Tags           []string
	HasFindings    *bool
	MinRiskScore   *int
	MaxRiskScore   *int
	// IDs keeps only these groups.
	IDs []shared.ID
	// DataScope, when set, computes every count and score of a group
	// (asset_count, the per-kind counts, risk_score, finding_count) over the
	// members in that data scope only, and filters and sorts on those values,
	// so a restricted reader learns nothing about assets outside their scope.
	// nil = every member.
	DataScope *shared.DataScope
}

// ListOptions contains options for listing asset groups.
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

// AllowedSortFields returns the allowed sort fields for asset groups.
func AllowedSortFields() map[string]string {
	return map[string]string{
		"name":          "name",
		"created_at":    "created_at",
		"updated_at":    "updated_at",
		"environment":   "environment",
		"criticality":   "criticality",
		"asset_count":   "asset_count",
		"risk_score":    "risk_score",
		"finding_count": "finding_count",
		"business_unit": "business_unit",
	}
}

// NewFilter creates an empty filter.
func NewFilter() Filter {
	return Filter{}
}

// WithTenantID adds a tenant ID filter.
func (f Filter) WithTenantID(tenantID string) Filter {
	f.TenantID = &tenantID
	return f
}

// WithSearch adds a search filter.
func (f Filter) WithSearch(search string) Filter {
	f.Search = &search
	return f
}

// WithEnvironments adds an environments filter.
func (f Filter) WithEnvironments(envs ...Environment) Filter {
	f.Environments = envs
	return f
}

// WithCriticalities adds a criticalities filter.
func (f Filter) WithCriticalities(crits ...Criticality) Filter {
	f.Criticalities = crits
	return f
}

// WithBusinessUnit adds a business unit filter.
func (f Filter) WithBusinessUnit(bu string) Filter {
	f.BusinessUnit = &bu
	return f
}

// WithBusinessUnitID adds a reconciled business-unit FK filter.
func (f Filter) WithBusinessUnitID(id string) Filter {
	f.BusinessUnitID = &id
	return f
}

// WithTags adds a tags filter.
func (f Filter) WithTags(tags ...string) Filter {
	f.Tags = tags
	return f
}

// WithHasFindings adds a has findings filter.
func (f Filter) WithHasFindings(hasFindings bool) Filter {
	f.HasFindings = &hasFindings
	return f
}

// Stats represents aggregated statistics for asset groups.
type Stats struct {
	Total            int64
	ByEnvironment    map[Environment]int64
	ByCriticality    map[Criticality]int64
	TotalAssets      int64
	TotalFindings    int64
	AverageRiskScore float64
}

// GroupAsset represents a simplified asset for group context.
type GroupAsset struct {
	ID           shared.ID
	Name         string
	Type         string
	Status       string
	RiskScore    int
	FindingCount int
	LastSeen     string
}

// ScanMemberQuery selects one keyset page of a group's scan members.
type ScanMemberQuery struct {
	TenantID shared.ID
	GroupID  shared.ID
	// AfterName and AfterID are the last member of the previous page; both
	// empty for the first page.
	AfterName string
	AfterID   shared.ID
	Limit     int
}

// ScanMember is a group member as scan dispatch sees it: its identity, the
// name a scanner is handed, and the properties that exclusions match.
type ScanMember struct {
	ID         shared.ID
	Name       string
	Type       string
	SubType    string // stored sub-type; scanner compatibility reads it
	Status     string
	Properties map[string]any // only the keys exclusion matching reads
}

// ScanMemberPage is one page of scan members. ArchivedCount (the group's
// archived members, which are never listed) is set on the first page only.
type ScanMemberPage struct {
	Members       []*ScanMember
	ArchivedCount int64
}

// GroupFinding represents a finding in group context (joined with asset info).
type GroupFinding struct {
	ID           shared.ID
	Title        string
	Severity     string
	Status       string
	AssetID      shared.ID
	AssetName    string
	AssetType    string
	DiscoveredAt string
}
