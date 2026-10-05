package app

// Compatibility shim — real impl lives in internal/app/accesscontrol/.
// Covers role, group, membership-cache, permission-cache,
// permission-version and group-sync services (RBAC bounded context).

import "github.com/openctemio/openctem/api/internal/app/accesscontrol"

type (
	PermissionCacheService      = accesscontrol.PermissionCacheService
	PermissionVersionService    = accesscontrol.PermissionVersionService
	RoleService                 = accesscontrol.RoleService
	RoleServiceOption           = accesscontrol.RoleServiceOption
	GroupService                = accesscontrol.GroupService
	GroupServiceOption          = accesscontrol.GroupServiceOption
	GroupSyncService            = accesscontrol.GroupSyncService
	MembershipCacheService      = accesscontrol.MembershipCacheService
	CachedMembership            = accesscontrol.CachedMembership
	AddGroupMemberInput         = accesscontrol.AddGroupMemberInput
	AssignAssetInput            = accesscontrol.AssignAssetInput
	AssignRoleInput             = accesscontrol.AssignRoleInput
	BulkAssignAssetsInput       = accesscontrol.BulkAssignAssetsInput
	BulkAssignAssetsResult      = accesscontrol.BulkAssignAssetsResult
	BulkAssignRoleToUsersInput  = accesscontrol.BulkAssignRoleToUsersInput
	BulkAssignRoleToUsersResult = accesscontrol.BulkAssignRoleToUsersResult
	CreateGroupInput            = accesscontrol.CreateGroupInput
	CreateRoleInput             = accesscontrol.CreateRoleInput
	GroupCounts                 = accesscontrol.GroupCounts
	ListGroupsInput             = accesscontrol.ListGroupsInput
	ListGroupsOutput            = accesscontrol.ListGroupsOutput
	SetUserRolesInput           = accesscontrol.SetUserRolesInput
	UnassignAssetInput          = accesscontrol.UnassignAssetInput
	UpdateAssetOwnershipInput   = accesscontrol.UpdateAssetOwnershipInput
	UpdateGroupInput            = accesscontrol.UpdateGroupInput
	UpdateGroupMemberRoleInput  = accesscontrol.UpdateGroupMemberRoleInput
	UpdateRoleInput             = accesscontrol.UpdateRoleInput
)

var (
	NewPermissionCacheService          = accesscontrol.NewPermissionCacheService
	NewPermissionVersionService        = accesscontrol.NewPermissionVersionService
	NewRoleService                     = accesscontrol.NewRoleService
	NewGroupService                    = accesscontrol.NewGroupService
	NewGroupSyncService                = accesscontrol.NewGroupSyncService
	NewMembershipCacheService          = accesscontrol.NewMembershipCacheService
	WithAccessControlRepository        = accesscontrol.WithAccessControlRepository
	WithGroupAuditService              = accesscontrol.WithGroupAuditService
	WithGroupDataScope                 = accesscontrol.WithGroupDataScope
	WithRoleAuditService               = accesscontrol.WithRoleAuditService
	WithRoleMembershipReader           = accesscontrol.WithRoleMembershipReader
	WithRolePermissionCacheService     = accesscontrol.WithRolePermissionCacheService
	WithRolePermissionVersionService   = accesscontrol.WithRolePermissionVersionService
	WithRoleMembershipCacheInvalidator = accesscontrol.WithRoleMembershipCacheInvalidator
	WithScopeDelegationCap             = accesscontrol.WithScopeDelegationCap
)
