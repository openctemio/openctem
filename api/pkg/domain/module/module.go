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
	isCore        bool
	releaseStatus ReleaseStatus

	// Parent module ID for hierarchical modules (sub-modules).
	// If nil, this is a top-level module.
	// Example: "integrations.scm" has parentModuleID = "integrations"
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
func (m *Module) IsCore() bool                 { return m.isCore }
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
	isCore bool,
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
		isCore:         isCore,
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

// AI Triage limit keys for PlanModule.Limits
const (
	AITriageLimitMonthlyTokens = "monthly_token_limit" // Monthly token limit (int64, -1 = unlimited)
)

// IsCoreModule returns true if the module is essential for platform operation.
func IsCoreModule(moduleID string) bool {
	return CoreModuleIDs[moduleID]
}

// IsUserFacing returns true if the module should be shown in the admin
// Module Management page. Internal modules are hidden.
func IsUserFacing(moduleID string) bool {
	return UserFacingModuleIDs[moduleID]
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
