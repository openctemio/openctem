package app

// Compatibility shim — real impl lives in internal/app/accesscontrol/.
// Covers role, group, membership-cache, permission-cache,
// permission-version, rule, group-sync services (RBAC bounded context).

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
	RuleService                 = accesscontrol.RuleService
	CachedMembership            = accesscontrol.CachedMembership
	AddGroupMemberInput         = accesscontrol.AddGroupMemberInput
	AssignAssetInput            = accesscontrol.AssignAssetInput
	AssignRoleInput             = accesscontrol.AssignRoleInput
	BulkAssignAssetsInput       = accesscontrol.BulkAssignAssetsInput
	BulkAssignAssetsResult      = accesscontrol.BulkAssignAssetsResult
	BulkAssignRoleToUsersInput  = accesscontrol.BulkAssignRoleToUsersInput
	BulkAssignRoleToUsersResult = accesscontrol.BulkAssignRoleToUsersResult
	CompleteBundleInput         = accesscontrol.CompleteBundleInput
	CreateBundleInput           = accesscontrol.CreateBundleInput
	CreateGroupInput            = accesscontrol.CreateGroupInput
	CreateOverrideInput         = accesscontrol.CreateOverrideInput
	CreateRoleInput             = accesscontrol.CreateRoleInput
	CreateSourceInput           = accesscontrol.CreateSourceInput
	GroupCounts                 = accesscontrol.GroupCounts
	ListBundlesInput            = accesscontrol.ListBundlesInput
	ListGroupsInput             = accesscontrol.ListGroupsInput
	ListGroupsOutput            = accesscontrol.ListGroupsOutput
	ListOverridesInput          = accesscontrol.ListOverridesInput
	ListRulesInput              = accesscontrol.ListRulesInput
	ListSourcesInput            = accesscontrol.ListSourcesInput
	SetUserRolesInput           = accesscontrol.SetUserRolesInput
	SyncResult                  = accesscontrol.SyncResult
	SyncSourceInput             = accesscontrol.SyncSourceInput
	UnassignAssetInput          = accesscontrol.UnassignAssetInput
	UpdateAssetOwnershipInput   = accesscontrol.UpdateAssetOwnershipInput
	UpdateGroupInput            = accesscontrol.UpdateGroupInput
	UpdateGroupMemberRoleInput  = accesscontrol.UpdateGroupMemberRoleInput
	UpdateOverrideInput         = accesscontrol.UpdateOverrideInput
	UpdateRoleInput             = accesscontrol.UpdateRoleInput
	UpdateSourceInput           = accesscontrol.UpdateSourceInput
)

var (
	NewPermissionCacheService          = accesscontrol.NewPermissionCacheService
	NewPermissionVersionService        = accesscontrol.NewPermissionVersionService
	NewRoleService                     = accesscontrol.NewRoleService
	NewGroupService                    = accesscontrol.NewGroupService
	NewGroupSyncService                = accesscontrol.NewGroupSyncService
	NewMembershipCacheService          = accesscontrol.NewMembershipCacheService
	NewRuleService                     = accesscontrol.NewRuleService
	WithAccessControlRepository        = accesscontrol.WithAccessControlRepository
	WithGroupAuditService              = accesscontrol.WithGroupAuditService
	WithRoleAuditService               = accesscontrol.WithRoleAuditService
	WithRoleMembershipReader           = accesscontrol.WithRoleMembershipReader
	WithRolePermissionCacheService     = accesscontrol.WithRolePermissionCacheService
	WithRolePermissionVersionService   = accesscontrol.WithRolePermissionVersionService
	WithRoleMembershipCacheInvalidator = accesscontrol.WithRoleMembershipCacheInvalidator

	ComputeContentHash    = accesscontrol.ComputeContentHash
	GenerateBundleVersion = accesscontrol.GenerateBundleVersion
)
