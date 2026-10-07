package permission

import "github.com/openctemio/openctem/api/pkg/domain/tenant"

// RolePermissions defines the default permissions for each role.
// This mapping can be overridden by configuration if needed.
//
// Permission hierarchy:
//   - Owner: Full access including team deletion and billing
//   - Admin: Full resource access + member management (no billing/team delete)
//   - Member: Read + Write access to resources (no delete, no member management,
//     no sensor writes, no audit log, no billing)
//   - Viewer: Read-only access to resources (no audit log, no billing)
var RolePermissions = map[tenant.Role][]Permission{
	tenant.RoleOwner: {
		// Core
		DashboardRead, DashboardAggregate,
		AuditRead,
		SettingsRead, SettingsWrite,
		// Assets
		AssetsRead, AssetsWrite, AssetsDelete, AssetsImport, AssetsExport,
		AssetGroupsRead, AssetGroupsWrite, AssetGroupsDelete,
		ComponentsRead, ComponentsWrite, ComponentsDelete,
		// Findings
		FindingsRead, FindingsWrite, FindingsDelete,
		FindingsAssign, FindingsTriage, FindingsStatus, FindingsExport, FindingsBulkUpdate, FindingsApprove,
		FindingsFixApply, FindingsVerify,
		ExposuresRead, ExposuresWrite, ExposuresDelete, ExposuresTriage,
		SuppressionsRead, SuppressionsWrite, SuppressionsDelete, SuppressionsApprove,
		VulnerabilitiesRead, VulnerabilitiesWrite, VulnerabilitiesDelete,
		CredentialsRead, CredentialsWrite, CredentialsReveal,
		RemediationRead, RemediationWrite,
		WorkflowsRead, WorkflowsWrite,
		// Scans
		ScansRead, ScansWrite, ScansDelete, ScansExecute,
		ScanProfilesRead, ScanProfilesWrite, ScanProfilesDelete,
		TemplateSourcesRead, TemplateSourcesWrite, TemplateSourcesDelete,
		ToolsRead, ToolsWrite, ToolsDelete,
		TenantToolsRead, TenantToolsWrite,
		ScannerTemplatesRead, ScannerTemplatesWrite, ScannerTemplatesDelete,
		SecretStoreRead, SecretStoreWrite, SecretStoreDelete,
		CIRead, CIWrite, CIOverride,
		ScanFreezeOverride,
		// Sensors
		SensorsRead, SensorsWrite, SensorsDelete,
		CommandsRead, CommandsWrite, CommandsDelete,
		ScanZonesRead, ScanZonesWrite, ScanZonesDelete,
		SensorsPair, SensorsApprove, SensorsGrantNarrow, SensorsGrantWiden, SensorsRevoke,
		// Team
		TeamRead, TeamUpdate, TeamDelete,
		MembersRead, MembersInvite, MembersWrite,
		GroupsRead, GroupsWrite, GroupsDelete, GroupsMembers, GroupsAssets,
		RolesRead, RolesWrite, RolesDelete, RolesAssign,
		AssignmentRulesRead, AssignmentRulesWrite, AssignmentRulesDelete,
		// Integrations
		IntegrationsRead, IntegrationsManage,
		SCMConnectionsRead, SCMConnectionsWrite, SCMConnectionsDelete,
		NotificationsRead, NotificationsWrite, NotificationsDelete,
		APIKeysRead, APIKeysWrite, APIKeysDelete,
		PipelinesRead, PipelinesWrite, PipelinesDelete, PipelinesExecute,
		// Settings
		SLARead, SLAWrite, SLADelete,
		// Attack Surface
		ScopeRead, ScopeWrite, ScopeDelete, ScopeExclusionsApprove, ScopeApprove,
		// Validation (legacy)
		PentestRead, PentestWrite,
		// Pentest (granular - all)
		PentestCampaignsRead, PentestCampaignsWrite, PentestCampaignsDelete,
		PentestFindingsRead, PentestFindingsWrite, PentestFindingsDelete,
		PentestRetestsRead, PentestRetestsWrite,
		PentestTemplatesRead, PentestTemplatesWrite,
		PentestReportsWrite,
		// Compliance (all)
		ComplianceFrameworksRead,
		ComplianceAssessmentsRead, ComplianceAssessmentsWrite,
		ComplianceMappingsRead, ComplianceMappingsWrite,
		// Reports
		ReportsRead, ReportsWrite,
		// Threat Intel
		ThreatIntelRead, ThreatIntelWrite,
		// AI Triage
		AITriageRead, AITriageTrigger,
		// CTEM (RFC-004 + RFC-005)
		CTEMCyclesRead, CTEMCyclesWrite,
		AttackerProfilesRead, AttackerProfilesWrite,
		BusinessServicesRead, BusinessServicesWrite,
		CompensatingControlsRead, CompensatingControlsWrite,
		PriorityRulesRead, PriorityRulesWrite,
		VerificationChecklistsRead, VerificationChecklistsWrite,
	},

	tenant.RoleAdmin: {
		// Core
		DashboardRead, DashboardAggregate,
		AuditRead,
		SettingsRead, SettingsWrite,
		// Assets
		AssetsRead, AssetsWrite, AssetsDelete, AssetsImport, AssetsExport,
		AssetGroupsRead, AssetGroupsWrite, AssetGroupsDelete,
		ComponentsRead, ComponentsWrite, ComponentsDelete,
		// Findings
		FindingsRead, FindingsWrite, FindingsDelete,
		FindingsAssign, FindingsTriage, FindingsStatus, FindingsExport, FindingsBulkUpdate, FindingsApprove,
		FindingsFixApply, FindingsVerify,
		ExposuresRead, ExposuresWrite, ExposuresDelete, ExposuresTriage,
		SuppressionsRead, SuppressionsWrite, SuppressionsDelete,
		VulnerabilitiesRead, VulnerabilitiesWrite, VulnerabilitiesDelete,
		CredentialsRead, CredentialsWrite, CredentialsReveal,
		RemediationRead, RemediationWrite,
		WorkflowsRead, WorkflowsWrite,
		// Scans
		ScansRead, ScansWrite, ScansDelete, ScansExecute,
		ScanProfilesRead, ScanProfilesWrite, ScanProfilesDelete,
		TemplateSourcesRead, TemplateSourcesWrite, TemplateSourcesDelete,
		ToolsRead, ToolsWrite, ToolsDelete,
		TenantToolsRead, TenantToolsWrite,
		ScannerTemplatesRead, ScannerTemplatesWrite, ScannerTemplatesDelete,
		SecretStoreRead, SecretStoreWrite, SecretStoreDelete,
		CIRead, CIWrite, CIOverride,
		ScanFreezeOverride,
		// Sensors
		SensorsRead, SensorsWrite, SensorsDelete,
		CommandsRead, CommandsWrite, CommandsDelete,
		ScanZonesRead, ScanZonesWrite, ScanZonesDelete,
		SensorsPair, SensorsApprove, SensorsGrantNarrow, SensorsGrantWiden, SensorsRevoke,
		// Team (no team:delete)
		TeamRead, TeamUpdate,
		MembersRead, MembersInvite, MembersWrite,
		GroupsRead, GroupsWrite, GroupsDelete, GroupsMembers, GroupsAssets,
		RolesRead, RolesWrite, RolesDelete, RolesAssign,
		AssignmentRulesRead, AssignmentRulesWrite, AssignmentRulesDelete,
		// Integrations
		IntegrationsRead, IntegrationsManage,
		SCMConnectionsRead, SCMConnectionsWrite, SCMConnectionsDelete,
		NotificationsRead, NotificationsWrite, NotificationsDelete,
		APIKeysRead, APIKeysWrite, APIKeysDelete,
		PipelinesRead, PipelinesWrite, PipelinesDelete, PipelinesExecute,
		// Settings (billing read only)
		SLARead, SLAWrite, SLADelete,
		// Attack Surface
		ScopeRead, ScopeWrite, ScopeDelete, ScopeExclusionsApprove, ScopeApprove,
		// Validation (legacy)
		PentestRead, PentestWrite,
		// Pentest (granular - all)
		PentestCampaignsRead, PentestCampaignsWrite, PentestCampaignsDelete,
		PentestFindingsRead, PentestFindingsWrite, PentestFindingsDelete,
		PentestRetestsRead, PentestRetestsWrite,
		PentestTemplatesRead, PentestTemplatesWrite,
		PentestReportsWrite,
		// Compliance (all)
		ComplianceFrameworksRead,
		ComplianceAssessmentsRead, ComplianceAssessmentsWrite,
		ComplianceMappingsRead, ComplianceMappingsWrite,
		// Reports
		ReportsRead, ReportsWrite,
		// Threat Intel
		ThreatIntelRead, ThreatIntelWrite,
		// AI Triage
		AITriageRead, AITriageTrigger,
		// CTEM (RFC-004 + RFC-005)
		CTEMCyclesRead, CTEMCyclesWrite,
		AttackerProfilesRead, AttackerProfilesWrite,
		BusinessServicesRead, BusinessServicesWrite,
		CompensatingControlsRead, CompensatingControlsWrite,
		PriorityRulesRead, PriorityRulesWrite,
		VerificationChecklistsRead, VerificationChecklistsWrite,
	},

	tenant.RoleMember: {
		// Core (the audit log is owner/admin only)
		DashboardRead,
		SettingsRead,
		// Assets (read + write, no delete)
		AssetsRead, AssetsWrite, AssetsImport,
		AssetGroupsRead, AssetGroupsWrite,
		ComponentsRead, ComponentsWrite,
		// Findings (read + write, no delete; fix_apply yes, verify no).
		// Assign + bulk_update are the granular action perms the member
		// effectively already held via findings:write before AUTHZ-05 split the
		// routes onto precise permissions — listed explicitly here so the role
		// matrix reflects real capability (behavior unchanged). Tightening the
		// member's assign/bulk grant is a separate product decision.
		FindingsRead, FindingsWrite,
		FindingsTriage, FindingsStatus, FindingsAssign, FindingsBulkUpdate, FindingsFixApply,
		ExposuresRead, ExposuresWrite, ExposuresTriage,
		SuppressionsRead,
		VulnerabilitiesRead,
		CredentialsRead,
		RemediationRead, RemediationWrite,
		WorkflowsRead,
		// Scans (read + write, no delete)
		ScansRead, ScansWrite, ScansExecute,
		ScanProfilesRead, ScanProfilesWrite,
		// Template sources and scanner templates: read only. A custom
		// template is code the sensors run, so writing one is owner/admin
		// only (owner decision 2026-10-02, migration 000262).
		TemplateSourcesRead,
		ToolsRead,
		TenantToolsRead, TenantToolsWrite,
		ScannerTemplatesRead,
		SecretStoreRead, SecretStoreWrite,
		CIRead, // CI trust and the gate are managed by owners and admins (RFC-051)
		// Sensors: read only. Creating sensors and minting, rotating or
		// revoking their keys is owner/admin only.
		SensorsRead,
		CommandsRead, CommandsWrite,
		ScanZonesRead, // zones are managed by owners and admins (RFC-023 D16)
		// Team (read only)
		TeamRead,
		MembersRead,
		GroupsRead,
		RolesRead,
		// Integrations (read + limited write)
		IntegrationsRead,
		SCMConnectionsRead, SCMConnectionsWrite,
		NotificationsRead,
		APIKeysRead,
		PipelinesRead, PipelinesWrite, PipelinesExecute,
		// Settings (read only; billing is owner/admin only)
		SLARead,
		// Attack Surface (read + write)
		ScopeRead, ScopeWrite,
		// Validation (legacy)
		PentestRead, PentestWrite,
		// Pentest (read + write, no delete)
		PentestCampaignsRead, PentestCampaignsWrite,
		PentestFindingsRead, PentestFindingsWrite,
		PentestRetestsRead, PentestRetestsWrite,
		PentestTemplatesRead, PentestTemplatesWrite,
		PentestReportsWrite,
		// Compliance (read + write assessments/mappings, no framework write)
		ComplianceFrameworksRead,
		ComplianceAssessmentsRead, ComplianceAssessmentsWrite,
		ComplianceMappingsRead, ComplianceMappingsWrite,
		// Reports (read + write)
		ReportsRead, ReportsWrite,
		// Threat Intel (read only)
		ThreatIntelRead,
		// AI Triage
		AITriageRead, AITriageTrigger,
		// CTEM — Members can read/write cycles/controls but cannot manage rules
		CTEMCyclesRead, CTEMCyclesWrite,
		AttackerProfilesRead,
		BusinessServicesRead, BusinessServicesWrite,
		CompensatingControlsRead, CompensatingControlsWrite,
		VerificationChecklistsRead, VerificationChecklistsWrite,
	},

	tenant.RoleViewer: {
		// Core (the audit log is owner/admin only)
		DashboardRead,
		SettingsRead,
		// Assets (read only)
		AssetsRead,
		AssetGroupsRead,
		ComponentsRead,
		// Findings (read only)
		FindingsRead,
		ExposuresRead,
		SuppressionsRead,
		VulnerabilitiesRead,
		CredentialsRead,
		RemediationRead,
		WorkflowsRead,
		// Scans (read only)
		ScansRead,
		ScanProfilesRead,
		TemplateSourcesRead,
		ToolsRead,
		TenantToolsRead,
		ScannerTemplatesRead,
		SecretStoreRead,
		CIRead,
		// Sensors (read only)
		SensorsRead,
		CommandsRead,
		ScanZonesRead,
		// Team (read only)
		TeamRead,
		MembersRead,
		GroupsRead,
		RolesRead,
		// Integrations (read only)
		IntegrationsRead,
		SCMConnectionsRead,
		NotificationsRead,
		APIKeysRead,
		PipelinesRead,
		// Settings (read only; billing is owner/admin only)
		SLARead,
		// Attack Surface (read only)
		ScopeRead,
		// Validation (legacy)
		PentestRead,
		// Pentest (read only)
		PentestCampaignsRead, PentestFindingsRead, PentestRetestsRead, PentestTemplatesRead,
		// Compliance (read only)
		ComplianceFrameworksRead, ComplianceAssessmentsRead, ComplianceMappingsRead,
		// Reports (read only)
		ReportsRead,
		// Threat Intel (read only)
		ThreatIntelRead,
		// AI Triage (read only)
		AITriageRead,
		// CTEM (read only)
		CTEMCyclesRead, AttackerProfilesRead, BusinessServicesRead,
		CompensatingControlsRead, VerificationChecklistsRead,
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
