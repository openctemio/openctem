package accesscontrol

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Repository defines the interface for access control persistence.
type Repository interface {
	// Asset Ownership
	CreateAssetOwner(ctx context.Context, ao *AssetOwner) error
	GetAssetOwner(ctx context.Context, assetID, groupID shared.ID) (*AssetOwner, error)
	UpdateAssetOwner(ctx context.Context, ao *AssetOwner) error
	DeleteAssetOwner(ctx context.Context, assetID, groupID shared.ID) error
	ListAssetOwners(ctx context.Context, assetID shared.ID) ([]*AssetOwner, error)
	ListAssetsByGroup(ctx context.Context, groupID shared.ID) ([]shared.ID, error)
	// scope limits the listed assets to the caller's data scope (nil: all).
	ListAssetOwnersByGroupWithDetails(ctx context.Context, groupID shared.ID, scope *shared.DataScope, limit, offset int) ([]*AssetOwnerWithAsset, int64, error)
	ListGroupsByAsset(ctx context.Context, assetID shared.ID) ([]shared.ID, error)
	CountAssetOwners(ctx context.Context, assetID shared.ID) (int64, error)
	CountAssetsByGroups(ctx context.Context, groupIDs []shared.ID) (map[shared.ID]int, error)
	HasPrimaryOwner(ctx context.Context, assetID shared.ID) (bool, error)

	// Extended Asset Ownership (with tenant isolation and user/group name resolution)
	GetAssetOwnerByID(ctx context.Context, id shared.ID) (*AssetOwner, error)
	GetAssetOwnerByUser(ctx context.Context, assetID, userID shared.ID) (*AssetOwner, error)
	DeleteAssetOwnerByID(ctx context.Context, id shared.ID) error
	DeleteAssetOwnerByUser(ctx context.Context, assetID, userID shared.ID) error
	ListAssetOwnersWithNames(ctx context.Context, tenantID, assetID shared.ID) ([]*AssetOwnerWithNames, error)
	GetPrimaryOwnerBrief(ctx context.Context, tenantID, assetID shared.ID) (*OwnerBrief, error)
	GetPrimaryOwnersByAssetIDs(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[string]*OwnerBrief, error)

	// One owner model: asset_owners is the only owner store (assets.owner_id
	// was folded into it by migration 000340).
	//
	// GetPrimaryUserOwnersByAssetIDs returns, per asset of the tenant, its
	// primary user owner: the earliest-assigned 'primary' row naming a user who
	// is a member of the tenant. Assets without one are absent from the map.
	GetPrimaryUserOwnersByAssetIDs(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]shared.ID, error)
	// FilterAssetsOwnedByUser returns the subset of assetIDs (of the tenant)
	// for which the user is a responsible owner: a 'primary' or 'secondary'
	// row naming the user directly.
	FilterAssetsOwnedByUser(ctx context.Context, tenantID, userID shared.ID, assetIDs []shared.ID) (map[shared.ID]bool, error)
	// SyncOwnerRefOwner makes userID the owner derived from the asset's
	// owner_ref: an 'owner_ref' row for any other user is removed and, when
	// userID is not nil and is a member of the tenant, a 'primary' row with
	// source 'owner_ref' is added unless the user already owns the asset.
	// Rows set by a person or a scope rule are never touched. A no-op for an
	// asset of another tenant.
	SyncOwnerRefOwner(ctx context.Context, tenantID, assetID shared.ID, userID *shared.ID) error
	// GetAssetOwnerSource returns the assignment_source of an asset_owners row
	// ('manual', 'scope_rule' or 'owner_ref').
	GetAssetOwnerSource(ctx context.Context, id shared.ID) (string, error)

	// Explicit per-user data-scope grants (asset_access_grants). Being an
	// owner does not grant access; a user's data scope is their groups' assets
	// plus these grants. Every method is tenant-scoped and keeps
	// user_accessible_assets in step in the same transaction.
	ListAssetAccessGrants(ctx context.Context, tenantID, assetID shared.ID) ([]*AssetAccessGrant, error)
	// CreateAssetAccessGrant grants the user (a member of the tenant) access
	// to the tenant's asset. ErrAccessGrantExists when it already exists.
	CreateAssetAccessGrant(ctx context.Context, tenantID, assetID, userID shared.ID, grantedBy *shared.ID) (*AssetAccessGrant, error)
	// DeleteAssetAccessGrant revokes the grant and returns it. The user keeps
	// the asset only if a group still gives access. ErrAccessGrantNotFound
	// when the grant is not on this asset of this tenant.
	DeleteAssetAccessGrant(ctx context.Context, tenantID, assetID, grantID shared.ID) (*AssetAccessGrant, error)

	// IsGroupInTenant reports whether the group belongs to the tenant. Used to
	// reject a cross-tenant principal before it is written as an asset owner
	// (asset_owners has no tenant_id column, so the principal is otherwise
	// unscoped). Mirrors the `groups WHERE tenant_id` screen used on reads.
	IsGroupInTenant(ctx context.Context, tenantID, groupID shared.ID) (bool, error)
	// IsUserInTenant reports whether the user is a member of the tenant.
	// Mirrors the `tenant_members WHERE tenant_id` screen used on reads.
	IsUserInTenant(ctx context.Context, tenantID, userID shared.ID) (bool, error)

	// User-Asset access queries
	ListAccessibleAssets(ctx context.Context, tenantID, userID shared.ID) ([]shared.ID, error)
	CanAccessAsset(ctx context.Context, userID, assetID shared.ID) (bool, error)
	GetUserAssetAccess(ctx context.Context, userID, assetID shared.ID) (*UserAssetAccess, error)

	// Assignment Rules
	CreateAssignmentRule(ctx context.Context, rule *AssignmentRule) error
	GetAssignmentRule(ctx context.Context, tenantID, id shared.ID) (*AssignmentRule, error)
	UpdateAssignmentRule(ctx context.Context, tenantID shared.ID, rule *AssignmentRule) error
	DeleteAssignmentRule(ctx context.Context, tenantID, id shared.ID) error
	ListAssignmentRules(ctx context.Context, tenantID shared.ID, filter AssignmentRuleFilter) ([]*AssignmentRule, error)
	CountAssignmentRules(ctx context.Context, tenantID shared.ID, filter AssignmentRuleFilter) (int64, error)
	ListActiveRulesByPriority(ctx context.Context, tenantID shared.ID) ([]*AssignmentRule, error)

	// Finding Group Assignments
	BulkCreateFindingGroupAssignments(ctx context.Context, fgas []*FindingGroupAssignment) (int, error)
	ListFindingGroupAssignments(ctx context.Context, tenantID, findingID shared.ID) ([]*FindingGroupAssignment, error)
	// BatchListFindingGroupIDs returns group IDs for multiple findings in 1 query.
	// Returns map[findingID][]groupID. Avoids N+1 in bulk operations.
	BatchListFindingGroupIDs(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID) (map[shared.ID][]shared.ID, error)
	CountFindingsByGroupFromRules(ctx context.Context, tenantID, groupID shared.ID) (int64, error)

	// Bulk operations
	BulkCreateAssetOwners(ctx context.Context, owners []*AssetOwner) (int, error)

	// Materialized view operations
	RefreshUserAccessibleAssets(ctx context.Context) error

	// Incremental access refresh (targeted updates instead of full refresh)
	RefreshAccessForAssetAssign(ctx context.Context, groupID, assetID shared.ID, ownershipType string) error
	RefreshAccessForAssetUnassign(ctx context.Context, groupID, assetID shared.ID) error
	RefreshAccessForMemberAdd(ctx context.Context, groupID, userID shared.ID) error
	RefreshAccessForMemberRemove(ctx context.Context, groupID, userID shared.ID) error

	// Scope Rules (dynamic asset-to-group scoping)
	CreateScopeRule(ctx context.Context, rule *ScopeRule) error
	GetScopeRule(ctx context.Context, tenantID, id shared.ID) (*ScopeRule, error)
	UpdateScopeRule(ctx context.Context, tenantID shared.ID, rule *ScopeRule) error
	DeleteScopeRule(ctx context.Context, tenantID, id shared.ID) error
	ListScopeRules(ctx context.Context, tenantID, groupID shared.ID, filter ScopeRuleFilter) ([]*ScopeRule, error)
	CountScopeRules(ctx context.Context, tenantID, groupID shared.ID, filter ScopeRuleFilter) (int64, error)
	ListActiveScopeRulesByTenant(ctx context.Context, tenantID shared.ID) ([]*ScopeRule, error)
	ListActiveScopeRulesByGroup(ctx context.Context, tenantID, groupID shared.ID) ([]*ScopeRule, error)

	// Scope rule asset operations
	CreateAssetOwnerWithSource(ctx context.Context, ao *AssetOwner, source string, ruleID *shared.ID) error
	BulkCreateAssetOwnersWithSource(ctx context.Context, owners []*AssetOwner, source string, ruleID *shared.ID) (int, error)
	DeleteAutoAssignedByRule(ctx context.Context, tenantID, ruleID shared.ID) (int, error)
	DeleteAutoAssignedForAsset(ctx context.Context, assetID, groupID shared.ID) error
	BulkDeleteAutoAssignedForAssets(ctx context.Context, assetIDs []shared.ID, groupID shared.ID) (int, error)
	ListAutoAssignedAssets(ctx context.Context, tenantID, groupID shared.ID) ([]shared.ID, error)
	ListAutoAssignedGroupsForAsset(ctx context.Context, assetID shared.ID) ([]shared.ID, error)

	// Transactional scope rule operations
	DeleteScopeRuleWithCleanup(ctx context.Context, tenantID, ruleID shared.ID) (int, error)

	// Scope rule matching queries
	FindAssetsByTagMatch(ctx context.Context, tenantID shared.ID, tags []string, logic MatchLogic) ([]shared.ID, error)
	FindAssetsByAssetGroupMatch(ctx context.Context, tenantID shared.ID, assetGroupIDs []shared.ID) ([]shared.ID, error)

	// Scope rule controller queries
	ListTenantsWithActiveScopeRules(ctx context.Context) ([]shared.ID, error)
	ListGroupsWithActiveScopeRules(ctx context.Context, tenantID shared.ID) ([]shared.ID, error)
	ListGroupsWithAssetGroupMatchRule(ctx context.Context, assetGroupID shared.ID) ([]shared.ID, error)
}

// AssignmentRuleFilter contains filter options for listing assignment rules.
type AssignmentRuleFilter struct {
	// Status filter
	IsActive *bool

	// Target group filter
	TargetGroupID *shared.ID

	// Search
	Search string

	// Pagination
	Limit  int
	Offset int

	// Sorting
	OrderBy   string // "name", "priority", "created_at"
	OrderDesc bool
}

// DefaultAssignmentRuleFilter returns a default filter.
func DefaultAssignmentRuleFilter() AssignmentRuleFilter {
	return AssignmentRuleFilter{
		Limit:     50,
		Offset:    0,
		OrderBy:   "priority",
		OrderDesc: true, // Higher priority first
	}
}

// ScopeRuleFilter contains filter options for listing scope rules.
type ScopeRuleFilter struct {
	IsActive *bool
	Limit    int
	Offset   int
}

// UserAssetAccess represents a user's access to an asset.
type UserAssetAccess struct {
	UserID        shared.ID
	AssetID       shared.ID
	OwnershipType OwnershipType
	GroupID       shared.ID
	GroupName     string
}

// UserAccessibleAsset represents an asset accessible by a user.
type UserAccessibleAsset struct {
	AssetID       shared.ID
	OwnershipType OwnershipType
	TenantID      shared.ID
}

// OwnerBrief is a lightweight owner representation for asset list responses.
type OwnerBrief struct {
	ID    string `json:"id"`
	Type  string `json:"type"` // "user" or "group"
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
}

// AssetOwnerWithNames extends AssetOwner with resolved user/group names.
type AssetOwnerWithNames struct {
	*AssetOwner
	UserName       string
	UserEmail      string
	GroupName      string
	AssignedByName string
	// AssignmentSource is 'manual', 'scope_rule' or 'owner_ref'.
	AssignmentSource string
}

// AssetAccessGrant is an explicit per-user data-scope grant on one asset.
type AssetAccessGrant struct {
	ID            shared.ID
	TenantID      shared.ID
	AssetID       shared.ID
	UserID        shared.ID
	UserName      string
	UserEmail     string
	Source        string // manual | migration (created from ownership in 2026-10)
	GrantedBy     *shared.ID
	GrantedByName string
	GrantedAt     time.Time
}

// AssetOwnerWithAsset extends AssetOwner with basic asset details.
type AssetOwnerWithAsset struct {
	*AssetOwner
	AssetName   string
	AssetType   string
	AssetStatus string
}

// AssetWithOwners represents an asset with its ownership information.
type AssetWithOwners struct {
	AssetID shared.ID
	Owners  []*AssetOwner
}

// GroupWithAssets represents a group with its owned assets.
type GroupWithAssets struct {
	GroupID  shared.ID
	AssetIDs []shared.ID
}
