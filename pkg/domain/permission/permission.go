// Package permission defines granular permissions for resource-based authorization.
//
// Permission naming convention follows hierarchical pattern:
//
//	{module}:{subfeature}:{action}
//
// Examples:
//   - integrations:scm:read (read SCM connections)
//   - assets:groups:write (manage asset groups)
//   - team:roles:assign (assign roles to users)
//
// For simpler permissions without subfeatures:
//
//	{module}:{action}
//
// Examples:
//   - dashboard:read
//   - assets:read
package permission

import "slices"

// Permission represents a granular permission for a specific action on a resource.
type Permission string

// String returns the string representation of the permission.
func (p Permission) String() string {
	return string(p)
}

// =============================================================================
// CORE MODULES
// =============================================================================

const (
	// Dashboard permissions
	DashboardRead Permission = "dashboard:read"

	// Audit log permissions
	AuditRead Permission = "audit:read"
)

// =============================================================================
// ASSETS MODULE
// =============================================================================

const (
	// Asset permissions (top-level)
	AssetsRead   Permission = "assets:read"
	AssetsWrite  Permission = "assets:write"
	AssetsDelete Permission = "assets:delete"

	// Asset Groups permissions (assets:groups:*)
	AssetGroupsRead   Permission = "assets:groups:read"
	AssetGroupsWrite  Permission = "assets:groups:write"
	AssetGroupsDelete Permission = "assets:groups:delete"

	// Component permissions (assets:components:*)
	// Note: Components (SBOM) is a separate module with its own permissions
	ComponentsRead   Permission = "assets:components:read"
	ComponentsWrite  Permission = "assets:components:write"
	ComponentsDelete Permission = "assets:components:delete"

	// Note: Repositories and Branches use general assets:* permissions
	// as they are just asset types, not separate security boundaries
)

// =============================================================================
// FINDINGS MODULE
// =============================================================================

const (
	// Finding permissions (findings:*)
	FindingsRead   Permission = "findings:read"
	FindingsWrite  Permission = "findings:write"
	FindingsDelete Permission = "findings:delete"

	// Suppression permissions (findings:suppressions:*)
	SuppressionsRead    Permission = "findings:suppressions:read"
	SuppressionsWrite   Permission = "findings:suppressions:write"
	SuppressionsDelete  Permission = "findings:suppressions:delete"
	SuppressionsApprove Permission = "findings:suppressions:approve"

	// Vulnerability permissions (findings:vulnerabilities:*)
	VulnerabilitiesRead   Permission = "findings:vulnerabilities:read"
	VulnerabilitiesWrite  Permission = "findings:vulnerabilities:write"
	VulnerabilitiesDelete Permission = "findings:vulnerabilities:delete"

	// Credential leak permissions (findings:credentials:*)
	CredentialsRead  Permission = "findings:credentials:read"
	CredentialsWrite Permission = "findings:credentials:write"

	// Remediation permissions (findings:remediation:*)
	RemediationRead  Permission = "findings:remediation:read"
	RemediationWrite Permission = "findings:remediation:write"

	// Workflow permissions (findings:workflows:*)
	WorkflowsRead  Permission = "findings:workflows:read"
	WorkflowsWrite Permission = "findings:workflows:write"

	// Policies permissions (findings:policies:*)
	PoliciesRead   Permission = "findings:policies:read"
	PoliciesWrite  Permission = "findings:policies:write"
	PoliciesDelete Permission = "findings:policies:delete"
)

// =============================================================================
// SCANS MODULE
// =============================================================================

const (
	// Scan permissions (scans:*)
	ScansRead    Permission = "scans:read"
	ScansWrite   Permission = "scans:write"
	ScansDelete  Permission = "scans:delete"
	ScansExecute Permission = "scans:execute"

	// Scan Profile permissions (scans:profiles:*)
	ScanProfilesRead   Permission = "scans:profiles:read"
	ScanProfilesWrite  Permission = "scans:profiles:write"
	ScanProfilesDelete Permission = "scans:profiles:delete"

	// Source permissions (scans:sources:*)
	SourcesRead   Permission = "scans:sources:read"
	SourcesWrite  Permission = "scans:sources:write"
	SourcesDelete Permission = "scans:sources:delete"

	// Tool Registry permissions (scans:tools:*)
	ToolsRead   Permission = "scans:tools:read"
	ToolsWrite  Permission = "scans:tools:write"
	ToolsDelete Permission = "scans:tools:delete"

	// Tenant Tool Config permissions (scans:tenant_tools:*)
	TenantToolsRead   Permission = "scans:tenant_tools:read"
	TenantToolsWrite  Permission = "scans:tenant_tools:write"
	TenantToolsDelete Permission = "scans:tenant_tools:delete"

	// Scanner Template permissions (scans:templates:*)
	ScannerTemplatesRead   Permission = "scans:templates:read"
	ScannerTemplatesWrite  Permission = "scans:templates:write"
	ScannerTemplatesDelete Permission = "scans:templates:delete"

	// Template Source permissions (scans:sources:*)
	TemplateSourcesRead   Permission = "scans:sources:read"
	TemplateSourcesWrite  Permission = "scans:sources:write"
	TemplateSourcesDelete Permission = "scans:sources:delete"

	// Secret Store permissions (scans:secret_store:*)
	SecretStoreRead   Permission = "scans:secret_store:read"
	SecretStoreWrite  Permission = "scans:secret_store:write"
	SecretStoreDelete Permission = "scans:secret_store:delete"
)

// =============================================================================
// AGENTS MODULE
// =============================================================================

const (
	// Agent permissions (agents:*)
	AgentsRead   Permission = "agents:read"
	AgentsWrite  Permission = "agents:write"
	AgentsDelete Permission = "agents:delete"

	// Command permissions (agents:commands:*)
	CommandsRead   Permission = "agents:commands:read"
	CommandsWrite  Permission = "agents:commands:write"
	CommandsDelete Permission = "agents:commands:delete"
)

// =============================================================================
// TEAM MODULE (Access Control)
// =============================================================================

const (
	// Team settings permissions (team:*)
	TeamRead   Permission = "team:read"
	TeamUpdate Permission = "team:update"
	TeamDelete Permission = "team:delete"

	// Member management permissions (team:members:*)
	MembersRead   Permission = "team:members:read"
	MembersInvite Permission = "team:members:invite"
	MembersWrite  Permission = "team:members:write"

	// Group permissions (team:groups:*)
	GroupsRead    Permission = "team:groups:read"
	GroupsWrite   Permission = "team:groups:write"
	GroupsDelete  Permission = "team:groups:delete"
	GroupsMembers Permission = "team:groups:members"
	GroupsAssets  Permission = "team:groups:assets"

	// Role permissions (team:roles:*)
	RolesRead   Permission = "team:roles:read"
	RolesWrite  Permission = "team:roles:write"
	RolesDelete Permission = "team:roles:delete"
	RolesAssign Permission = "team:roles:assign"

	// Permission Set permissions (team:permission_sets:*)
	PermissionSetsRead   Permission = "team:permission_sets:read"
	PermissionSetsWrite  Permission = "team:permission_sets:write"
	PermissionSetsDelete Permission = "team:permission_sets:delete"

	// Assignment Rules permissions (team:assignment_rules:*)
	AssignmentRulesRead   Permission = "team:assignment_rules:read"
	AssignmentRulesWrite  Permission = "team:assignment_rules:write"
	AssignmentRulesDelete Permission = "team:assignment_rules:delete"
)

// =============================================================================
// INTEGRATIONS MODULE
// =============================================================================

const (
	// Integration permissions (integrations:*)
	IntegrationsRead   Permission = "integrations:read"
	IntegrationsManage Permission = "integrations:manage"

	// SCM Connection permissions (integrations:scm:*)
	SCMConnectionsRead   Permission = "integrations:scm:read"
	SCMConnectionsWrite  Permission = "integrations:scm:write"
	SCMConnectionsDelete Permission = "integrations:scm:delete"

	// Notification permissions (integrations:notifications:*)
	NotificationsRead   Permission = "integrations:notifications:read"
	NotificationsWrite  Permission = "integrations:notifications:write"
	NotificationsDelete Permission = "integrations:notifications:delete"

	// Webhook permissions (integrations:webhooks:*)
	WebhooksRead   Permission = "integrations:webhooks:read"
	WebhooksWrite  Permission = "integrations:webhooks:write"
	WebhooksDelete Permission = "integrations:webhooks:delete"

	// API Keys permissions (integrations:api_keys:*)
	APIKeysRead   Permission = "integrations:api_keys:read"
	APIKeysWrite  Permission = "integrations:api_keys:write"
	APIKeysDelete Permission = "integrations:api_keys:delete"

	// Pipeline permissions (integrations:pipelines:*)
	PipelinesRead    Permission = "integrations:pipelines:read"
	PipelinesWrite   Permission = "integrations:pipelines:write"
	PipelinesDelete  Permission = "integrations:pipelines:delete"
	PipelinesExecute Permission = "integrations:pipelines:execute"
)

// =============================================================================
// SETTINGS MODULE
// =============================================================================

const (
	// Billing permissions (settings:billing:*)
	BillingRead  Permission = "settings:billing:read"
	BillingWrite Permission = "settings:billing:write"

	// SLA permissions (settings:sla:*)
	SLARead   Permission = "settings:sla:read"
	SLAWrite  Permission = "settings:sla:write"
	SLADelete Permission = "settings:sla:delete"
)

// =============================================================================
// ATTACK SURFACE MODULE (CTEM Scoping)
// =============================================================================

const (
	// Scope permissions (attack_surface:scope:*)
	ScopeRead   Permission = "attack_surface:scope:read"
	ScopeWrite  Permission = "attack_surface:scope:write"
	ScopeDelete Permission = "attack_surface:scope:delete"
)

// =============================================================================
// VALIDATION MODULE (CTEM)
// =============================================================================

const (
	// Pentest/Validation permissions (validation:*)
	ValidationRead  Permission = "validation:read"
	ValidationWrite Permission = "validation:write"
)

// =============================================================================
// REPORTS MODULE
// =============================================================================

const (
	// Report permissions (reports:*)
	ReportsRead  Permission = "reports:read"
	ReportsWrite Permission = "reports:write"
)

// =============================================================================
// LEGACY ALIASES (for backward compatibility in code)
// These map to new standardized permissions but keep old constant names
// =============================================================================

const (
	// MembersManage is an alias for MembersWrite (team:members:write)
	MembersManage Permission = "team:members:write"

	// BillingManage is an alias for BillingWrite (settings:billing:write)
	BillingManage Permission = "settings:billing:write"

	// PentestRead/Write are aliases for ValidationRead/Write
	PentestRead  Permission = "validation:read"
	PentestWrite Permission = "validation:write"

	// GroupsPermissions is an alias for GroupsWrite (team:groups:write)
	GroupsPermissions Permission = "team:groups:write"
)

// AllPermissions returns all defined permissions.
// Useful for validation and documentation.
func AllPermissions() []Permission {
	return []Permission{
		// Core
		DashboardRead,
		AuditRead,

		// Assets module
		AssetsRead, AssetsWrite, AssetsDelete,
		AssetGroupsRead, AssetGroupsWrite, AssetGroupsDelete,
		ComponentsRead, ComponentsWrite, ComponentsDelete,

		// Findings module
		FindingsRead, FindingsWrite, FindingsDelete,
		SuppressionsRead, SuppressionsWrite, SuppressionsDelete, SuppressionsApprove,
		VulnerabilitiesRead, VulnerabilitiesWrite, VulnerabilitiesDelete,
		CredentialsRead, CredentialsWrite,
		RemediationRead, RemediationWrite,
		WorkflowsRead, WorkflowsWrite,
		PoliciesRead, PoliciesWrite, PoliciesDelete,

		// Scans module
		ScansRead, ScansWrite, ScansDelete, ScansExecute,
		ScanProfilesRead, ScanProfilesWrite, ScanProfilesDelete,
		SourcesRead, SourcesWrite, SourcesDelete,
		ToolsRead, ToolsWrite, ToolsDelete,
		TenantToolsRead, TenantToolsWrite, TenantToolsDelete,
		ScannerTemplatesRead, ScannerTemplatesWrite, ScannerTemplatesDelete,
		SecretStoreRead, SecretStoreWrite, SecretStoreDelete,

		// Agents module
		AgentsRead, AgentsWrite, AgentsDelete,
		CommandsRead, CommandsWrite, CommandsDelete,

		// Team module
		TeamRead, TeamUpdate, TeamDelete,
		MembersRead, MembersInvite, MembersWrite, MembersManage,
		GroupsRead, GroupsWrite, GroupsDelete, GroupsMembers, GroupsAssets, GroupsPermissions,
		RolesRead, RolesWrite, RolesDelete, RolesAssign,
		PermissionSetsRead, PermissionSetsWrite, PermissionSetsDelete,
		AssignmentRulesRead, AssignmentRulesWrite, AssignmentRulesDelete,

		// Integrations module
		IntegrationsRead, IntegrationsManage,
		SCMConnectionsRead, SCMConnectionsWrite, SCMConnectionsDelete,
		NotificationsRead, NotificationsWrite, NotificationsDelete,
		WebhooksRead, WebhooksWrite, WebhooksDelete,
		APIKeysRead, APIKeysWrite, APIKeysDelete,
		PipelinesRead, PipelinesWrite, PipelinesDelete, PipelinesExecute,

		// Settings module
		BillingRead, BillingWrite, BillingManage,
		SLARead, SLAWrite, SLADelete,

		// Attack Surface module
		ScopeRead, ScopeWrite, ScopeDelete,

		// Validation module
		ValidationRead, ValidationWrite, PentestRead, PentestWrite,

		// Reports module
		ReportsRead, ReportsWrite,
	}
}

// IsValid checks if the permission is a known permission.
func (p Permission) IsValid() bool {
	return slices.Contains(AllPermissions(), p)
}

// ParsePermission parses a string to a Permission.
func ParsePermission(s string) (Permission, bool) {
	p := Permission(s)
	return p, p.IsValid()
}

// ToStrings converts a slice of Permissions to a slice of strings.
func ToStrings(perms []Permission) []string {
	result := make([]string, len(perms))
	for i, p := range perms {
		result[i] = p.String()
	}
	return result
}

// FromStrings converts a slice of strings to a slice of Permissions.
// Invalid permissions are skipped.
func FromStrings(strs []string) []Permission {
	result := make([]Permission, 0, len(strs))
	for _, s := range strs {
		if p, ok := ParsePermission(s); ok {
			result = append(result, p)
		}
	}
	return result
}

// Contains checks if a permission slice contains a specific permission.
func Contains(perms []Permission, target Permission) bool {
	return slices.Contains(perms, target)
}

// ContainsAny checks if a permission slice contains any of the target permissions.
func ContainsAny(perms []Permission, targets ...Permission) bool {
	for _, target := range targets {
		if Contains(perms, target) {
			return true
		}
	}
	return false
}

// ContainsAll checks if a permission slice contains all of the target permissions.
func ContainsAll(perms []Permission, targets ...Permission) bool {
	for _, target := range targets {
		if !Contains(perms, target) {
			return false
		}
	}
	return true
}
