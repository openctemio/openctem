package module

// ReleaseStatus represents the product lifecycle status of a module.
type ReleaseStatus string

const (
	// ReleaseStatusReleased means the module is generally available.
	ReleaseStatusReleased ReleaseStatus = "released"
	// ReleaseStatusComingSoon means the module is not released yet, shown as preview.
	ReleaseStatusComingSoon ReleaseStatus = "coming_soon"
	// ReleaseStatusBeta means the module is in beta testing.
	ReleaseStatusBeta ReleaseStatus = "beta"
	// ReleaseStatusDeprecated means the module is being phased out.
	ReleaseStatusDeprecated ReleaseStatus = "deprecated"
)

// Module represents a feature module in the system.
type Module struct {
	id            string
	slug          string
	name          string
	description   string
	icon          string
	category      string
	displayOrder  int
	isActive      bool
	releaseStatus ReleaseStatus

	// Parent module ID for hierarchical modules (sub-modules).
	// If nil, this is a top-level module.
	// Example: "assets.domains" has parentModuleID = "assets"
	parentModuleID *string

	// Event types associated with this module (for notification filtering)
	eventTypes []string
}

// Getters for Module

func (m *Module) ID() string                   { return m.id }
func (m *Module) Slug() string                 { return m.slug }
func (m *Module) Name() string                 { return m.name }
func (m *Module) Description() string          { return m.description }
func (m *Module) Icon() string                 { return m.icon }
func (m *Module) Category() string             { return m.category }
func (m *Module) DisplayOrder() int            { return m.displayOrder }
func (m *Module) IsActive() bool               { return m.isActive }
func (m *Module) ReleaseStatus() ReleaseStatus { return m.releaseStatus }
func (m *Module) ParentModuleID() *string      { return m.parentModuleID }
func (m *Module) EventTypes() []string         { return m.eventTypes }

// IsSubModule returns true if this module has a parent module.
func (m *Module) IsSubModule() bool { return m.parentModuleID != nil }

// HasParent returns true if this module's parent is the given ID.
func (m *Module) HasParent(parentID string) bool {
	return m.parentModuleID != nil && *m.parentModuleID == parentID
}

// IsReleased returns true if the module is generally available.
func (m *Module) IsReleased() bool { return m.releaseStatus == ReleaseStatusReleased }

// IsComingSoon returns true if the module is not released yet.
func (m *Module) IsComingSoon() bool { return m.releaseStatus == ReleaseStatusComingSoon }

// IsBeta returns true if the module is in beta testing.
func (m *Module) IsBeta() bool { return m.releaseStatus == ReleaseStatusBeta }

// IsDeprecated returns true if the module is being phased out.
func (m *Module) IsDeprecated() bool { return m.releaseStatus == ReleaseStatusDeprecated }

// SubModuleSeparator is the separator used in sub-module IDs (e.g., "integrations.scm").
const SubModuleSeparator = "."

// SubModuleSlugSeparator is the separator used in sub-module slugs (e.g., "integrations-scm").
const SubModuleSlugSeparator = "-"

// BuildSubModuleID constructs a sub-module ID from parent and child.
// Example: BuildSubModuleID("integrations", "scm") returns "integrations.scm"
func BuildSubModuleID(parentModuleID, subModuleName string) string {
	return parentModuleID + SubModuleSeparator + subModuleName
}

// BuildSubModuleSlug constructs a sub-module slug from parent and child.
// Example: BuildSubModuleSlug("integrations", "scm") returns "integrations-scm"
func BuildSubModuleSlug(parentModuleID, subModuleName string) string {
	return parentModuleID + SubModuleSlugSeparator + subModuleName
}

// ValidateSubModuleID validates that a sub-module ID follows the correct format.
// Returns error if the ID is malformed (e.g., double separator, empty parts).
func ValidateSubModuleID(fullSubModuleID string) error {
	// Check for empty string
	if fullSubModuleID == "" {
		return ErrInvalidSubModuleID
	}

	// Check for double separator (common mistake: "integrations.integrations.scm")
	doubleSep := SubModuleSeparator + SubModuleSeparator
	if len(fullSubModuleID) > len(doubleSep) {
		for i := 0; i < len(fullSubModuleID)-len(doubleSep)+1; i++ {
			if fullSubModuleID[i:i+len(doubleSep)] == doubleSep {
				return ErrInvalidSubModuleID
			}
		}
	}

	return nil
}

// ReconstructModule creates a Module from stored data.
func ReconstructModule(
	id, slug, name, description, icon, category string,
	displayOrder int,
	isActive bool,
	releaseStatus string,
	parentModuleID *string,
	eventTypes []string,
) *Module {
	// Default to released if not specified
	status := ReleaseStatus(releaseStatus)
	if status == "" {
		status = ReleaseStatusReleased
	}

	return &Module{
		id:             id,
		slug:           slug,
		name:           name,
		description:    description,
		icon:           icon,
		category:       category,
		displayOrder:   displayOrder,
		isActive:       isActive,
		releaseStatus:  status,
		parentModuleID: parentModuleID,
		eventTypes:     eventTypes,
	}
}

// ModuleCategory constants
const (
	ModuleCategoryCore       = "core"
	ModuleCategorySecurity   = "security"
	ModuleCategoryPlatform   = "platform"
	ModuleCategoryCompliance = "compliance"
	ModuleCategoryEnterprise = "enterprise"
)

// Well-known module IDs (top-level modules)
const (
	// Core
	ModuleDashboard = "dashboard"
	ModuleAssets    = "assets"
	ModuleFindings  = "findings"
	ModuleScans     = "scans"

	// Discovery
	ModuleCredentials    = "credentials"
	ModuleComponents     = "components"
	ModuleBranches       = "branches"
	ModuleVulnerabilities = "vulnerabilities"

	// Prioritization
	ModuleThreatIntel = "threat_intel"
	ModuleExposures   = "exposures"
	ModuleAITriage    = "ai_triage"
	ModuleSLA         = "sla"

	// Validation
	ModulePentest = "pentest"

	// Mobilization
	ModuleRemediation  = "remediation"
	ModuleSuppressions = "suppressions"
	ModulePolicies     = "policies"

	// Insights
	ModuleReports = "reports"
	ModuleAudit   = "audit"

	// Settings
	ModuleIntegrations        = "integrations"
	ModuleAgents              = "agents"
	ModuleTeam                = "team"
	ModuleGroups              = "groups"
	ModuleRoles               = "roles"
	ModuleSettings            = "settings"
	ModuleAPIKeys             = "api_keys"
	ModuleWebhooks            = "webhooks"
	ModuleNotificationSettings = "notification_settings"

	// Data
	ModuleSources = "sources"
	ModuleSecrets = "secrets"
	ModuleScope   = "scope"

	// Operations
	ModulePipelines    = "pipelines"
	ModuleTools        = "tools"
	ModuleCommands     = "commands"
	ModuleScanProfiles = "scan_profiles"
	ModuleIOCs         = "iocs"
)

// Integration sub-module IDs (children of ModuleIntegrations)
const (
	ModuleIntegrationsSCM           = "integrations.scm"
	ModuleIntegrationsNotifications = "integrations.notifications"
	ModuleIntegrationsWebhooks      = "integrations.webhooks"
	ModuleIntegrationsAPI           = "integrations.api"
	ModuleIntegrationsPipelines     = "integrations.pipelines"
	ModuleIntegrationsTicketing     = "integrations.ticketing"
	ModuleIntegrationsSIEM          = "integrations.siem"
)

// AI Triage sub-module IDs (children of ModuleAITriage)
const (
	ModuleAITriageBulk          = "ai_triage.bulk"           // Bulk triage operations
	ModuleAITriageAuto          = "ai_triage.auto"           // Auto-triage on finding creation
	ModuleAITriageWorkflow      = "ai_triage.workflow"       // Workflow triggers and actions
	ModuleAITriageBYOK          = "ai_triage.byok"           // Bring Your Own Key mode
	ModuleAITriageAgent         = "ai_triage.agent"          // Self-hosted Agent mode
	ModuleAITriageCustomPrompts = "ai_triage.custom_prompts" // Custom prompt templates
)

// AI Triage limit keys for PlanModule.Limits
const (
	AITriageLimitMonthlyTokens = "monthly_token_limit" // Monthly token limit (int64, -1 = unlimited)
)

// ModulePermissionMapping maps module IDs to their required read permissions.
// This is used to filter modules based on user's RBAC permissions.
// A user must have at least the read permission to see the module in sidebar.
// These permissions MUST match the permission IDs seeded in 000005_permissions.up.sql
var ModulePermissionMapping = map[string]string{
	// Core modules
	ModuleDashboard: "dashboard:read",
	ModuleAssets:    "assets:read",
	ModuleFindings:  "findings:read",
	ModuleScans:     "scans:read",

	// Discovery modules (hierarchical under parent modules)
	ModuleCredentials:     "findings:credentials:read",
	ModuleComponents:      "assets:components:read",
	ModuleBranches:        "assets:read", // Branches are asset types, use assets:read
	ModuleVulnerabilities: "findings:vulnerabilities:read",

	// Prioritization modules
	ModuleThreatIntel: "threat_intel:read",
	ModuleExposures:   "findings:exposures:read",
	ModuleAITriage:    "ai_triage:read",
	ModuleSLA:         "settings:sla:read",

	// Validation modules
	ModulePentest: "validation:read",

	// Mobilization modules
	ModuleRemediation:  "findings:remediation:read",
	ModuleSuppressions: "findings:suppressions:read",
	ModulePolicies:     "findings:policies:read",

	// Insights modules
	ModuleReports: "reports:read",
	ModuleAudit:   "audit:read",

	// Settings modules
	ModuleIntegrations:         "integrations:read",
	ModuleAgents:               "agents:read",
	ModuleTeam:                 "team:read",
	ModuleGroups:               "team:groups:read",
	ModuleRoles:                "team:roles:read",
	ModuleSettings:             "settings:read",
	ModuleAPIKeys:              "integrations:api_keys:read",
	ModuleWebhooks:             "integrations:webhooks:read",
	ModuleNotificationSettings: "integrations:notifications:read",

	// Data modules
	ModuleSources: "scans:sources:read",
	ModuleSecrets: "scans:secret_store:read",
	ModuleScope:   "attack_surface:scope:read",

	// Operations modules
	ModulePipelines:    "integrations:pipelines:read",
	ModuleTools:        "scans:tools:read",
	ModuleScanProfiles: "scans:profiles:read",
}

// GetRequiredPermission returns the required permission for a module.
// Returns empty string if the module has no permission requirement.
func GetRequiredPermission(moduleID string) string {
	if perm, ok := ModulePermissionMapping[moduleID]; ok {
		return perm
	}
	return ""
}

// FilterModulesByPermissions filters modules based on user's permissions.
// Returns only modules that the user has at least read permission for.
// Admin/Owner users should pass isAdmin=true to bypass permission checks.
func FilterModulesByPermissions(modules []*Module, userPermissions []string, isAdmin bool) []*Module {
	// Admin/Owner bypass permission checks
	if isAdmin {
		return modules
	}

	// Create a set for faster lookup
	permSet := make(map[string]bool, len(userPermissions))
	for _, p := range userPermissions {
		permSet[p] = true
	}

	filtered := make([]*Module, 0, len(modules))
	for _, m := range modules {
		requiredPerm := GetRequiredPermission(m.ID())

		// If no permission required, include the module
		if requiredPerm == "" {
			filtered = append(filtered, m)
			continue
		}

		// Check if user has the required permission
		if permSet[requiredPerm] {
			filtered = append(filtered, m)
		}
	}

	return filtered
}


// FilterModuleIDsByPermissions filters module IDs based on user's permissions.
func FilterModuleIDsByPermissions(moduleIDs []string, userPermissions []string, isAdmin bool) []string {
	// Admin/Owner bypass permission checks
	if isAdmin {
		return moduleIDs
	}

	// Create a set for faster lookup
	permSet := make(map[string]bool, len(userPermissions))
	for _, p := range userPermissions {
		permSet[p] = true
	}

	filtered := make([]string, 0, len(moduleIDs))
	for _, id := range moduleIDs {
		requiredPerm := GetRequiredPermission(id)

		// If no permission required, include the module
		if requiredPerm == "" {
			filtered = append(filtered, id)
			continue
		}

		// Check if user has the required permission
		if permSet[requiredPerm] {
			filtered = append(filtered, id)
		}
	}

	return filtered
}
