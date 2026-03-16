package accesscontrol

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
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
	ListAssetOwnersByGroupWithDetails(ctx context.Context, groupID shared.ID, limit, offset int) ([]*AssetOwnerWithAsset, int64, error)
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

	// Incremental access refresh for direct user ownership
	RefreshAccessForDirectOwnerAdd(ctx context.Context, assetID, userID shared.ID, ownershipType string) error
	RefreshAccessForDirectOwnerRemove(ctx context.Context, assetID, userID shared.ID) error

	// User-Asset access queries
	ListAccessibleAssets(ctx context.Context, tenantID, userID shared.ID) ([]shared.ID, error)
	CanAccessAsset(ctx context.Context, userID, assetID shared.ID) (bool, error)
	GetUserAssetAccess(ctx context.Context, userID, assetID shared.ID) (*UserAssetAccess, error)
	// HasAnyScopeAssignment checks if a user has any rows in user_accessible_assets.
	// Used for backward compat: if false, user sees all data (no groups configured).
	HasAnyScopeAssignment(ctx context.Context, tenantID, userID shared.ID) (bool, error)

	// Group Permissions (custom overrides)
	CreateGroupPermission(ctx context.Context, gp *GroupPermission) error
	GetGroupPermission(ctx context.Context, groupID shared.ID, permissionID string) (*GroupPermission, error)
	UpdateGroupPermission(ctx context.Context, gp *GroupPermission) error
	DeleteGroupPermission(ctx context.Context, groupID shared.ID, permissionID string) error
	ListGroupPermissions(ctx context.Context, groupID shared.ID) ([]*GroupPermission, error)
	ListGroupPermissionsByEffect(ctx context.Context, groupID shared.ID, effect PermissionEffect) ([]*GroupPermission, error)

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
	Type  string `json:"type"`  // "user" or "group"
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
}

// AssetOwnerWithNames extends AssetOwner with resolved user/group names.
type AssetOwnerWithNames struct {
	*AssetOwner
	UserName   string
	UserEmail  string
	GroupName  string
	AssignedByName string
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
