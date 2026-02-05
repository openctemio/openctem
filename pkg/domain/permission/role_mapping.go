package permission

import "github.com/openctemio/api/pkg/domain/tenant"

// RolePermissions defines the default permissions for each role.
// This mapping can be overridden by configuration if needed.
//
// Permission hierarchy:
//   - Owner: Full access including team deletion and billing
//   - Admin: Full resource access + member management (no billing/team delete)
//   - Member: Read + Write access to resources (no delete, no member management)
//   - Viewer: Read-only access to resources
var RolePermissions = map[tenant.Role][]Permission{
	tenant.RoleOwner: {
		// Core
		DashboardRead,
		AuditRead,
		// Assets
		AssetsRead, AssetsWrite, AssetsDelete,
		AssetGroupsRead, AssetGroupsWrite, AssetGroupsDelete,
		ComponentsRead, ComponentsWrite, ComponentsDelete,
		// Findings
		FindingsRead, FindingsWrite, FindingsDelete,
		SuppressionsRead, SuppressionsWrite, SuppressionsDelete, SuppressionsApprove,
		VulnerabilitiesRead, VulnerabilitiesWrite, VulnerabilitiesDelete,
		CredentialsRead, CredentialsWrite,
		RemediationRead, RemediationWrite,
		WorkflowsRead, WorkflowsWrite,
		PoliciesRead, PoliciesWrite, PoliciesDelete,
		// Scans
		ScansRead, ScansWrite, ScansDelete, ScansExecute,
		ScanProfilesRead, ScanProfilesWrite, ScanProfilesDelete,
		SourcesRead, SourcesWrite, SourcesDelete,
		ToolsRead, ToolsWrite, ToolsDelete,
		TenantToolsRead, TenantToolsWrite, TenantToolsDelete,
		ScannerTemplatesRead, ScannerTemplatesWrite, ScannerTemplatesDelete,
		SecretStoreRead, SecretStoreWrite, SecretStoreDelete,
		// Agents
		AgentsRead, AgentsWrite, AgentsDelete,
		CommandsRead, CommandsWrite, CommandsDelete,
		// Team
		TeamRead, TeamUpdate, TeamDelete,
		MembersRead, MembersInvite, MembersWrite,
		GroupsRead, GroupsWrite, GroupsDelete, GroupsMembers, GroupsAssets,
		RolesRead, RolesWrite, RolesDelete, RolesAssign,
		PermissionSetsRead, PermissionSetsWrite, PermissionSetsDelete,
		AssignmentRulesRead, AssignmentRulesWrite, AssignmentRulesDelete,
		// Integrations
		IntegrationsRead, IntegrationsManage,
		SCMConnectionsRead, SCMConnectionsWrite, SCMConnectionsDelete,
		NotificationsRead, NotificationsWrite, NotificationsDelete,
		WebhooksRead, WebhooksWrite, WebhooksDelete,
		APIKeysRead, APIKeysWrite, APIKeysDelete,
		PipelinesRead, PipelinesWrite, PipelinesDelete, PipelinesExecute,
		// Settings
		BillingRead, BillingWrite,
		SLARead, SLAWrite, SLADelete,
		// Attack Surface
		ScopeRead, ScopeWrite, ScopeDelete,
		// Validation
		ValidationRead, ValidationWrite,
		// Reports
		ReportsRead, ReportsWrite,
	},

	tenant.RoleAdmin: {
		// Core
		DashboardRead,
		AuditRead,
		// Assets
		AssetsRead, AssetsWrite, AssetsDelete,
		AssetGroupsRead, AssetGroupsWrite, AssetGroupsDelete,
		ComponentsRead, ComponentsWrite, ComponentsDelete,
		// Findings
		FindingsRead, FindingsWrite, FindingsDelete,
		SuppressionsRead, SuppressionsWrite, SuppressionsDelete,
		VulnerabilitiesRead, VulnerabilitiesWrite, VulnerabilitiesDelete,
		CredentialsRead, CredentialsWrite,
		RemediationRead, RemediationWrite,
		WorkflowsRead, WorkflowsWrite,
		PoliciesRead, PoliciesWrite, PoliciesDelete,
		// Scans
		ScansRead, ScansWrite, ScansDelete, ScansExecute,
		ScanProfilesRead, ScanProfilesWrite, ScanProfilesDelete,
		SourcesRead, SourcesWrite, SourcesDelete,
		ToolsRead, ToolsWrite, ToolsDelete,
		TenantToolsRead, TenantToolsWrite, TenantToolsDelete,
		ScannerTemplatesRead, ScannerTemplatesWrite, ScannerTemplatesDelete,
		SecretStoreRead, SecretStoreWrite, SecretStoreDelete,
		// Agents
		AgentsRead, AgentsWrite, AgentsDelete,
		CommandsRead, CommandsWrite, CommandsDelete,
		// Team (no team:delete)
		TeamRead, TeamUpdate,
		MembersRead, MembersInvite, MembersWrite,
		GroupsRead, GroupsWrite, GroupsDelete, GroupsMembers, GroupsAssets,
		RolesRead, RolesWrite, RolesDelete, RolesAssign,
		PermissionSetsRead, PermissionSetsWrite, PermissionSetsDelete,
		AssignmentRulesRead, AssignmentRulesWrite, AssignmentRulesDelete,
		// Integrations
		IntegrationsRead, IntegrationsManage,
		SCMConnectionsRead, SCMConnectionsWrite, SCMConnectionsDelete,
		NotificationsRead, NotificationsWrite, NotificationsDelete,
		WebhooksRead, WebhooksWrite, WebhooksDelete,
		APIKeysRead, APIKeysWrite, APIKeysDelete,
		PipelinesRead, PipelinesWrite, PipelinesDelete, PipelinesExecute,
		// Settings (billing read only)
		BillingRead,
		SLARead, SLAWrite, SLADelete,
		// Attack Surface
		ScopeRead, ScopeWrite, ScopeDelete,
		// Validation
		ValidationRead, ValidationWrite,
		// Reports
		ReportsRead, ReportsWrite,
	},

	tenant.RoleMember: {
		// Core
		DashboardRead,
		AuditRead,
		// Assets (read + write, no delete)
		AssetsRead, AssetsWrite,
		AssetGroupsRead, AssetGroupsWrite,
		ComponentsRead, ComponentsWrite,
		// Findings (read + write, no delete)
		FindingsRead, FindingsWrite,
		SuppressionsRead,
		VulnerabilitiesRead,
		CredentialsRead,
		RemediationRead, RemediationWrite,
		WorkflowsRead,
		PoliciesRead,
		// Scans (read + write, no delete)
		ScansRead, ScansWrite, ScansExecute,
		ScanProfilesRead, ScanProfilesWrite,
		SourcesRead, SourcesWrite,
		ToolsRead,
		TenantToolsRead, TenantToolsWrite,
		ScannerTemplatesRead, ScannerTemplatesWrite,
		SecretStoreRead, SecretStoreWrite,
		// Agents (read + write, no delete)
		AgentsRead, AgentsWrite,
		CommandsRead, CommandsWrite,
		// Team (read only)
		TeamRead,
		MembersRead,
		GroupsRead,
		RolesRead,
		PermissionSetsRead,
		// Integrations (read + limited write)
		IntegrationsRead,
		SCMConnectionsRead, SCMConnectionsWrite,
		NotificationsRead,
		WebhooksRead,
		APIKeysRead,
		PipelinesRead, PipelinesWrite,
		// Settings (read only)
		BillingRead,
		SLARead,
		// Attack Surface (read + write)
		ScopeRead, ScopeWrite,
		// Validation (read + write)
		ValidationRead, ValidationWrite,
		// Reports (read + write)
		ReportsRead, ReportsWrite,
	},

	tenant.RoleViewer: {
		// Core
		DashboardRead,
		AuditRead,
		// Assets (read only)
		AssetsRead,
		AssetGroupsRead,
		ComponentsRead,
		// Findings (read only)
		FindingsRead,
		SuppressionsRead,
		VulnerabilitiesRead,
		CredentialsRead,
		RemediationRead,
		WorkflowsRead,
		PoliciesRead,
		// Scans (read only)
		ScansRead,
		ScanProfilesRead,
		SourcesRead,
		ToolsRead,
		TenantToolsRead,
		ScannerTemplatesRead,
		SecretStoreRead,
		// Agents (read only)
		AgentsRead,
		CommandsRead,
		// Team (read only)
		TeamRead,
		MembersRead,
		GroupsRead,
		RolesRead,
		PermissionSetsRead,
		// Integrations (read only)
		IntegrationsRead,
		SCMConnectionsRead,
		NotificationsRead,
		WebhooksRead,
		APIKeysRead,
		PipelinesRead,
		// Settings (read only)
		BillingRead,
		SLARead,
		// Attack Surface (read only)
		ScopeRead,
		// Validation (read only)
		ValidationRead,
		// Reports (read only)
		ReportsRead,
	},
}

// GetPermissionsForRole returns the permissions for a given role.
// Returns empty slice if role is not found.
func GetPermissionsForRole(role tenant.Role) []Permission {
	if perms, ok := RolePermissions[role]; ok {
		return perms
	}
	return []Permission{}
}

// GetPermissionStringsForRole returns the permissions as strings for a given role.
// This is useful for JWT token generation.
func GetPermissionStringsForRole(role tenant.Role) []string {
	return ToStrings(GetPermissionsForRole(role))
}

// HasPermission checks if a role has a specific permission.
func HasPermission(role tenant.Role, perm Permission) bool {
	return Contains(GetPermissionsForRole(role), perm)
}

// HasAnyPermission checks if a role has any of the specified permissions.
func HasAnyPermission(role tenant.Role, perms ...Permission) bool {
	return ContainsAny(GetPermissionsForRole(role), perms...)
}

// HasAllPermissions checks if a role has all of the specified permissions.
func HasAllPermissions(role tenant.Role, perms ...Permission) bool {
	return ContainsAll(GetPermissionsForRole(role), perms...)
}

// CanRead checks if a role has read permission for a resource.
func CanRead(role tenant.Role, resource string) bool {
	perm := Permission(resource + ":read")
	return HasPermission(role, perm)
}

// CanWrite checks if a role has write permission for a resource.
func CanWrite(role tenant.Role, resource string) bool {
	perm := Permission(resource + ":write")
	return HasPermission(role, perm)
}

// CanDelete checks if a role has delete permission for a resource.
func CanDelete(role tenant.Role, resource string) bool {
	perm := Permission(resource + ":delete")
	return HasPermission(role, perm)
}
