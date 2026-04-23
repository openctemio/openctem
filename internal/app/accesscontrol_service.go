package app

// Compatibility shim — real impl lives in internal/app/accesscontrol/.
// Covers permission, role, group, membership-cache, permission-cache,
// permission-version, rule, group-sync services (RBAC bounded context).

import "github.com/openctemio/api/internal/app/accesscontrol"

type (
	PermissionService           = accesscontrol.PermissionService
	PermissionServiceOption     = accesscontrol.PermissionServiceOption
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
	AddPermissionToSetInput     = accesscontrol.AddPermissionToSetInput
	AssignAssetInput            = accesscontrol.AssignAssetInput
	AssignPermissionSetInput    = accesscontrol.AssignPermissionSetInput
	AssignRoleInput             = accesscontrol.AssignRoleInput
	BulkAssignAssetsInput       = accesscontrol.BulkAssignAssetsInput
	BulkAssignAssetsResult      = accesscontrol.BulkAssignAssetsResult
	BulkAssignRoleToUsersInput  = accesscontrol.BulkAssignRoleToUsersInput
	BulkAssignRoleToUsersResult = accesscontrol.BulkAssignRoleToUsersResult
	CompleteBundleInput         = accesscontrol.CompleteBundleInput
	CreateBundleInput           = accesscontrol.CreateBundleInput
	CreateGroupInput            = accesscontrol.CreateGroupInput
	CreateGroupPermissionInput  = accesscontrol.CreateGroupPermissionInput
	CreateOverrideInput         = accesscontrol.CreateOverrideInput
	CreatePermissionSetInput    = accesscontrol.CreatePermissionSetInput
	CreateRoleInput             = accesscontrol.CreateRoleInput
	CreateSourceInput           = accesscontrol.CreateSourceInput
	GroupCounts                 = accesscontrol.GroupCounts
	ListBundlesInput            = accesscontrol.ListBundlesInput
	ListGroupsInput             = accesscontrol.ListGroupsInput
	ListGroupsOutput            = accesscontrol.ListGroupsOutput
	ListOverridesInput          = accesscontrol.ListOverridesInput
	ListPermissionSetsInput     = accesscontrol.ListPermissionSetsInput
	ListPermissionSetsOutput    = accesscontrol.ListPermissionSetsOutput
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
	UpdatePermissionSetInput    = accesscontrol.UpdatePermissionSetInput
	UpdateRoleInput             = accesscontrol.UpdateRoleInput
	UpdateSourceInput           = accesscontrol.UpdateSourceInput
)

var (
	NewPermissionService                  = accesscontrol.NewPermissionService
	NewPermissionCacheService             = accesscontrol.NewPermissionCacheService
	NewPermissionVersionService           = accesscontrol.NewPermissionVersionService
	NewRoleService                        = accesscontrol.NewRoleService
	NewGroupService                       = accesscontrol.NewGroupService
	NewGroupSyncService                   = accesscontrol.NewGroupSyncService
	NewMembershipCacheService             = accesscontrol.NewMembershipCacheService
	NewRuleService                        = accesscontrol.NewRuleService
	WithAccessControlRepository           = accesscontrol.WithAccessControlRepository
	WithGroupAuditService                 = accesscontrol.WithGroupAuditService
	WithPermissionAccessControlRepository = accesscontrol.WithPermissionAccessControlRepository
	WithPermissionAuditService            = accesscontrol.WithPermissionAuditService
	WithPermissionGroupRepository         = accesscontrol.WithPermissionGroupRepository
	WithPermissionSetRepository           = accesscontrol.WithPermissionSetRepository
	WithRoleAuditService                  = accesscontrol.WithRoleAuditService
	WithRolePermissionCacheService        = accesscontrol.WithRolePermissionCacheService
	WithRolePermissionVersionService      = accesscontrol.WithRolePermissionVersionService

	ComputeContentHash    = accesscontrol.ComputeContentHash
	GenerateBundleVersion = accesscontrol.GenerateBundleVersion
)
