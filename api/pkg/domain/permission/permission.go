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
	// DashboardAggregate shows organization-wide dashboard totals to a viewer
	// whose data scope is restricted (owner decision D6, research doc 15):
	// without it, a restricted viewer's dashboard counts only their own
	// assets and findings. Breakdowns under 5 are left out (k-floor).
	DashboardAggregate Permission = "dashboard:aggregate"

	// Audit log permissions
	AuditRead Permission = "audit:read"

	// Settings permissions (settings:*)
	SettingsRead  Permission = "settings:read"
	SettingsWrite Permission = "settings:write"
)

// =============================================================================
// ASSETS MODULE
// =============================================================================

const (
	// Asset permissions (top-level)
	AssetsRead   Permission = "assets:read"
	AssetsWrite  Permission = "assets:write"
	AssetsDelete Permission = "assets:delete"

	// Asset import/export
	AssetsImport Permission = "assets:import"
	AssetsExport Permission = "assets:export"

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
	FindingsRead       Permission = "findings:read"
	FindingsWrite      Permission = "findings:write"
	FindingsDelete     Permission = "findings:delete"
	FindingsAssign     Permission = "findings:assign"
	FindingsTriage     Permission = "findings:triage"
	FindingsStatus     Permission = "findings:status"
	FindingsExport     Permission = "findings:export"
	FindingsBulkUpdate Permission = "findings:bulk_update"
	FindingsApprove    Permission = "findings:approve"
	FindingsFixApply   Permission = "findings:fix_apply" // in_progress → fix_applied (dev/owner action)
	FindingsVerify     Permission = "findings:verify"    // fix_applied → resolved (security/scanner action)
	// FindingsComment: comment on a finding and react to comments. Split
	// from findings:write so a person can discuss a finding without the
	// other writes (migration 001486).
	FindingsComment Permission = "findings:comment"
	// FindingsSeverity: change a finding's severity or classification. Split
	// from findings:write so whoever fixes a finding need not be able to
	// re-score it (migration 001486).
	FindingsSeverity Permission = "findings:severity"

	// Exposure permissions (findings:exposures:*)
	ExposuresRead   Permission = "findings:exposures:read"
	ExposuresWrite  Permission = "findings:exposures:write"
	ExposuresDelete Permission = "findings:exposures:delete"
	ExposuresTriage Permission = "findings:exposures:triage"

	// Suppression permissions (findings:suppressions:*)
	SuppressionsRead    Permission = "findings:suppressions:read"
	SuppressionsWrite   Permission = "findings:suppressions:write"
	SuppressionsDelete  Permission = "findings:suppressions:delete"
	SuppressionsApprove Permission = "findings:suppressions:approve"

	// Vulnerability permissions (findings:vulnerabilities:*)
	VulnerabilitiesRead Permission = "findings:vulnerabilities:read"

	// Credential leak permissions (findings:credentials:*)
	CredentialsRead  Permission = "findings:credentials:read"
	CredentialsWrite Permission = "findings:credentials:write"
	// CredentialsReveal returns a leaked credential's plaintext secret. Read
	// returns only a mask and a fingerprint; every reveal is audited.
	CredentialsReveal Permission = "findings:credentials:reveal"
	// EvidenceReveal returns the plaintext of secret values masked out of a
	// finding's evidence (request headers, cookies, tokens). Needs step-up;
	// every reveal is audited and shown on the finding's timeline.
	EvidenceReveal Permission = "findings:evidence:reveal"

	// Remediation permissions (findings:remediation:*)
	RemediationRead  Permission = "findings:remediation:read"
	RemediationWrite Permission = "findings:remediation:write"

	// Workflow permissions (findings:workflows:*)
	WorkflowsRead  Permission = "findings:workflows:read"
	WorkflowsWrite Permission = "findings:workflows:write"
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

	// Template source permissions (scans:sources:*)
	TemplateSourcesRead   Permission = "scans:sources:read"
	TemplateSourcesWrite  Permission = "scans:sources:write"
	TemplateSourcesDelete Permission = "scans:sources:delete"

	// Tool Registry permissions (scans:tools:*)
	ToolsRead   Permission = "scans:tools:read"
	ToolsWrite  Permission = "scans:tools:write"
	ToolsDelete Permission = "scans:tools:delete"

	// Tenant Tool Config permissions (scans:tenant_tools:*)
	TenantToolsRead  Permission = "scans:tenant_tools:read"
	TenantToolsWrite Permission = "scans:tenant_tools:write"

	// Scanner Template permissions (scans:templates:*)
	ScannerTemplatesRead   Permission = "scans:templates:read"
	ScannerTemplatesWrite  Permission = "scans:templates:write"
	ScannerTemplatesDelete Permission = "scans:templates:delete"

	// Content pack permissions (scans:content:*, RFC-061)
	ContentPacksRead  Permission = "scans:content:read"
	ContentPacksWrite Permission = "scans:content:write"

	// Secret Store permissions (scans:secret_store:*)
	SecretStoreRead   Permission = "scans:secret_store:read"
	SecretStoreWrite  Permission = "scans:secret_store:write"
	SecretStoreDelete Permission = "scans:secret_store:delete"

	// CI runs, CI trust configurations and the CI gate (scans:ci:*,
	// RFC-051). Write (trust configurations issue upload credentials, gate
	// policies decide what blocks a scan workflow) and override (break-glass) are
	// admin-only.
	CIRead     Permission = "scans:ci:read"
	CIWrite    Permission = "scans:ci:write"
	CIOverride Permission = "scans:ci:override"

	// ScanFreezeOverride starts a scan by hand while a scan freeze window
	// is active (audited). Managing the windows themselves needs
	// sensors:zones:write / sensors:zones:delete.
	ScanFreezeOverride Permission = "scans:freeze:override"
)

// =============================================================================
// AGENTS MODULE
// =============================================================================

const (
	// Sensor permissions (sensors:*)
	SensorsRead   Permission = "sensors:read"
	SensorsWrite  Permission = "sensors:write"
	SensorsDelete Permission = "sensors:delete"

	// Command permissions (sensors:commands:*)
	CommandsRead   Permission = "sensors:commands:read"
	CommandsWrite  Permission = "sensors:commands:write"
	CommandsDelete Permission = "sensors:commands:delete"

	// Scan zone permissions (sensors:zones:*, RFC-023 D16). Write covers
	// creating/editing zones and assigning sensors to them.
	ScanZonesRead   Permission = "sensors:zones:read"
	ScanZonesWrite  Permission = "sensors:zones:write"
	ScanZonesDelete Permission = "sensors:zones:delete"

	// Pairing and per-sensor grants (RFC-052). Pair: look up a pairing
	// code, expect a sensor, deny a request. Approve: bind a sensor key to
	// the organization (with step-up). GrantNarrow / GrantWiden: narrow or
	// widen a sensor's grant and demote or promote its trust level. Revoke:
	// revoke a sensor or one of its keys.
	SensorsPair        Permission = "sensors:pair"
	SensorsApprove     Permission = "sensors:approve"
	SensorsGrantNarrow Permission = "sensors:grant:narrow"
	SensorsGrantWiden  Permission = "sensors:grant:widen"
	SensorsRevoke      Permission = "sensors:revoke"
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

	// API Keys permissions (integrations:api_keys:*)
	APIKeysRead   Permission = "integrations:api_keys:read"
	APIKeysWrite  Permission = "integrations:api_keys:write"
	APIKeysDelete Permission = "integrations:api_keys:delete"

	// Scan workflow permissions (scans:workflows:*): the graph of steps a Scan runs
	ScanWorkflowsRead   Permission = "scans:workflows:read"
	ScanWorkflowsWrite  Permission = "scans:workflows:write"
	ScanWorkflowsDelete Permission = "scans:workflows:delete"
)

// =============================================================================
// SETTINGS MODULE
// =============================================================================

const (

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
	// ScopeExclusionsApprove approves or rejects a pending scope exclusion.
	// An exclusion suppresses scanning, so scope:write only requests one;
	// owners and admins hold this by default.
	ScopeExclusionsApprove Permission = "attack_surface:scope:exclusions:approve"
	// ScopeApprove creates effective scope entries and approves or rejects
	// scope requests and widenings (RFC-054). Without it, scope:write only
	// requests a one-off entry; owners and admins hold it by default.
	ScopeApprove Permission = "attack_surface:scope:approve"
)

// =============================================================================
// VALIDATION MODULE (CTEM)
// =============================================================================

const (
	// Pentest/validation permissions (validation:*): the module-wide gate
	// of pentest, simulations and control tests.
	PentestRead  Permission = "validation:read"
	PentestWrite Permission = "validation:write"

	// Granular pentest permissions (pentest:*)
	PentestCampaignsRead   Permission = "pentest:campaigns:read"
	PentestCampaignsWrite  Permission = "pentest:campaigns:write"
	PentestCampaignsDelete Permission = "pentest:campaigns:delete"
	PentestFindingsRead    Permission = "pentest:findings:read"
	PentestFindingsWrite   Permission = "pentest:findings:write"
	PentestFindingsDelete  Permission = "pentest:findings:delete"
	PentestRetestsRead     Permission = "pentest:retests:read"
	PentestRetestsWrite    Permission = "pentest:retests:write"
	PentestTemplatesRead   Permission = "pentest:templates:read"
	PentestTemplatesWrite  Permission = "pentest:templates:write"
	PentestReportsWrite    Permission = "pentest:reports:write"
)

// =============================================================================
// COMPLIANCE MODULE
// =============================================================================

const (
	ComplianceFrameworksRead   Permission = "compliance:frameworks:read"
	ComplianceAssessmentsRead  Permission = "compliance:assessments:read"
	ComplianceAssessmentsWrite Permission = "compliance:assessments:write"
	ComplianceMappingsRead     Permission = "compliance:mappings:read"
	ComplianceMappingsWrite    Permission = "compliance:mappings:write"
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
// THREAT INTELLIGENCE MODULE
// =============================================================================

const (
	// Threat Intel permissions (threat_intel:*)
	ThreatIntelRead  Permission = "threat_intel:read"
	ThreatIntelWrite Permission = "threat_intel:write"
)

// =============================================================================
// CTEM (Continuous Threat Exposure Management) MODULE
// RFC-004 + RFC-005 features
// =============================================================================

const (
	// CTEM Cycles — time-boxed assessment periods (RFC-005 Gap 3)
	CTEMCyclesRead  Permission = "ctem:cycles:read"
	CTEMCyclesWrite Permission = "ctem:cycles:write"

	// Attacker Profiles — threat model profiles (RFC-005 Gap 9)
	AttackerProfilesRead  Permission = "ctem:attacker_profiles:read"
	AttackerProfilesWrite Permission = "ctem:attacker_profiles:write"

	// Business Services — business capability mapping (Phase 3)
	BusinessServicesRead  Permission = "ctem:business_services:read"
	BusinessServicesWrite Permission = "ctem:business_services:write"

	// Compensating Controls — risk-mitigating controls (RFC-005 Gap 6)
	CompensatingControlsRead  Permission = "ctem:compensating_controls:read"
	CompensatingControlsWrite Permission = "ctem:compensating_controls:write"

	// Priority Override Rules — per-tenant classification rules (RFC-004)
	PriorityRulesRead  Permission = "ctem:priority_rules:read"
	PriorityRulesWrite Permission = "ctem:priority_rules:write"

	// Verification Checklist — finding closure criteria (RFC-005 Gap 8)
	VerificationChecklistsRead  Permission = "ctem:verification_checklists:read"
	VerificationChecklistsWrite Permission = "ctem:verification_checklists:write"
)

// =============================================================================
// AI TRIAGE MODULE
// =============================================================================

const (
	// AI Triage permissions (ai_triage:*)
	AITriageRead    Permission = "ai_triage:read"
	AITriageTrigger Permission = "ai_triage:trigger"
)

// AllPermissions returns all defined permissions.
// Useful for validation and documentation.
func AllPermissions() []Permission {
	return []Permission{
		// Core
		DashboardRead, DashboardAggregate,
		AuditRead,
		SettingsRead, SettingsWrite,

		// Assets module
		AssetsRead, AssetsWrite, AssetsDelete, AssetsImport, AssetsExport,
		AssetGroupsRead, AssetGroupsWrite, AssetGroupsDelete,
		ComponentsRead, ComponentsWrite, ComponentsDelete,

		// Findings module
		FindingsRead, FindingsWrite, FindingsDelete,
		FindingsAssign, FindingsTriage, FindingsStatus, FindingsExport, FindingsBulkUpdate, FindingsApprove,
		FindingsFixApply, FindingsVerify, FindingsComment, FindingsSeverity,
		ExposuresRead, ExposuresWrite, ExposuresDelete, ExposuresTriage,
		SuppressionsRead, SuppressionsWrite, SuppressionsDelete, SuppressionsApprove,
		VulnerabilitiesRead,
		CredentialsRead, CredentialsWrite, CredentialsReveal, EvidenceReveal,
		RemediationRead, RemediationWrite,
		WorkflowsRead, WorkflowsWrite,

		// Scans module
		ScansRead, ScansWrite, ScansDelete, ScansExecute,
		ScanProfilesRead, ScanProfilesWrite, ScanProfilesDelete,
		TemplateSourcesRead, TemplateSourcesWrite, TemplateSourcesDelete,
		ToolsRead, ToolsWrite, ToolsDelete,
		TenantToolsRead, TenantToolsWrite,
		ScannerTemplatesRead, ScannerTemplatesWrite, ScannerTemplatesDelete,
		ContentPacksRead, ContentPacksWrite,
		SecretStoreRead, SecretStoreWrite, SecretStoreDelete,
		CIRead, CIWrite, CIOverride,
		ScanFreezeOverride,

		// Sensors module
		SensorsRead, SensorsWrite, SensorsDelete,
		CommandsRead, CommandsWrite, CommandsDelete,
		ScanZonesRead, ScanZonesWrite, ScanZonesDelete,
		SensorsPair, SensorsApprove, SensorsGrantNarrow, SensorsGrantWiden, SensorsRevoke,

		// Team module
		TeamRead, TeamUpdate, TeamDelete,
		MembersRead, MembersInvite, MembersWrite,
		GroupsRead, GroupsWrite, GroupsDelete, GroupsMembers, GroupsAssets,
		RolesRead, RolesWrite, RolesDelete, RolesAssign,
		AssignmentRulesRead, AssignmentRulesWrite, AssignmentRulesDelete,

		// Integrations module
		IntegrationsRead, IntegrationsManage,
		SCMConnectionsRead, SCMConnectionsWrite, SCMConnectionsDelete,
		NotificationsRead, NotificationsWrite, NotificationsDelete,
		APIKeysRead, APIKeysWrite, APIKeysDelete,
		ScanWorkflowsRead, ScanWorkflowsWrite, ScanWorkflowsDelete,

		// Settings module
		SLARead, SLAWrite, SLADelete,

		// Attack Surface module
		ScopeRead, ScopeWrite, ScopeDelete, ScopeExclusionsApprove, ScopeApprove,

		// Validation module (legacy)
		PentestRead, PentestWrite,

		// Pentest module (granular)
		PentestCampaignsRead, PentestCampaignsWrite, PentestCampaignsDelete,
		PentestFindingsRead, PentestFindingsWrite, PentestFindingsDelete,
		PentestRetestsRead, PentestRetestsWrite,
		PentestTemplatesRead, PentestTemplatesWrite,
		PentestReportsWrite,

		// Compliance module
		ComplianceFrameworksRead,
		ComplianceAssessmentsRead, ComplianceAssessmentsWrite,
		ComplianceMappingsRead, ComplianceMappingsWrite,

		// Reports module
		ReportsRead, ReportsWrite,

		// Threat Intel module
		ThreatIntelRead, ThreatIntelWrite,

		// AI Triage module
		AITriageRead, AITriageTrigger,

		// CTEM module (RFC-004 + RFC-005)
		CTEMCyclesRead, CTEMCyclesWrite,
		AttackerProfilesRead, AttackerProfilesWrite,
		BusinessServicesRead, BusinessServicesWrite,
		CompensatingControlsRead, CompensatingControlsWrite,
		PriorityRulesRead, PriorityRulesWrite,
		VerificationChecklistsRead, VerificationChecklistsWrite,
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
