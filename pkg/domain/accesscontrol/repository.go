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
	ListGroupsByAsset(ctx context.Context, assetID shared.ID) ([]shared.ID, error)
	CountAssetOwners(ctx context.Context, assetID shared.ID) (int64, error)
	HasPrimaryOwner(ctx context.Context, assetID shared.ID) (bool, error)

	// User-Asset access queries
	ListAccessibleAssets(ctx context.Context, tenantID, userID shared.ID) ([]shared.ID, error)
	CanAccessAsset(ctx context.Context, userID, assetID shared.ID) (bool, error)
	GetUserAssetAccess(ctx context.Context, userID, assetID shared.ID) (*UserAssetAccess, error)

	// Group Permissions (custom overrides)
	CreateGroupPermission(ctx context.Context, gp *GroupPermission) error
	GetGroupPermission(ctx context.Context, groupID shared.ID, permissionID string) (*GroupPermission, error)
	UpdateGroupPermission(ctx context.Context, gp *GroupPermission) error
	DeleteGroupPermission(ctx context.Context, groupID shared.ID, permissionID string) error
	ListGroupPermissions(ctx context.Context, groupID shared.ID) ([]*GroupPermission, error)
	ListGroupPermissionsByEffect(ctx context.Context, groupID shared.ID, effect PermissionEffect) ([]*GroupPermission, error)

	// Assignment Rules
	CreateAssignmentRule(ctx context.Context, rule *AssignmentRule) error
	GetAssignmentRule(ctx context.Context, id shared.ID) (*AssignmentRule, error)
	UpdateAssignmentRule(ctx context.Context, rule *AssignmentRule) error
	DeleteAssignmentRule(ctx context.Context, id shared.ID) error
	ListAssignmentRules(ctx context.Context, tenantID shared.ID, filter AssignmentRuleFilter) ([]*AssignmentRule, error)
	CountAssignmentRules(ctx context.Context, tenantID shared.ID, filter AssignmentRuleFilter) (int64, error)
	ListActiveRulesByPriority(ctx context.Context, tenantID shared.ID) ([]*AssignmentRule, error)

	// Materialized view operations
	RefreshUserAccessibleAssets(ctx context.Context) error
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
