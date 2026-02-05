package accesscontrol

import "slices"

// OwnershipType represents the type of asset ownership.
type OwnershipType string

const (
	// OwnershipPrimary is the main owner with full access and primary responsibility.
	OwnershipPrimary OwnershipType = "primary"
	// OwnershipSecondary is a co-owner with full access and shared responsibility.
	OwnershipSecondary OwnershipType = "secondary"
	// OwnershipStakeholder has view access and receives critical notifications only.
	OwnershipStakeholder OwnershipType = "stakeholder"
	// OwnershipInformed has no access but receives summary notifications only.
	OwnershipInformed OwnershipType = "informed"
)

// AllOwnershipTypes returns all valid ownership types.
func AllOwnershipTypes() []OwnershipType {
	return []OwnershipType{
		OwnershipPrimary,
		OwnershipSecondary,
		OwnershipStakeholder,
		OwnershipInformed,
	}
}

// IsValid checks if the ownership type is valid.
func (t OwnershipType) IsValid() bool {
	return slices.Contains(AllOwnershipTypes(), t)
}

// String returns the string representation.
func (t OwnershipType) String() string {
	return string(t)
}

// HasFullAccess checks if this ownership type grants full access.
func (t OwnershipType) HasFullAccess() bool {
	return t == OwnershipPrimary || t == OwnershipSecondary
}

// HasViewAccess checks if this ownership type grants view access.
func (t OwnershipType) HasViewAccess() bool {
	return t == OwnershipPrimary || t == OwnershipSecondary || t == OwnershipStakeholder
}

// ReceivesNotifications checks if this ownership type receives notifications.
func (t OwnershipType) ReceivesNotifications() bool {
	return t != OwnershipInformed
}

// ReceivesAllNotifications checks if this ownership type receives all notifications.
func (t OwnershipType) ReceivesAllNotifications() bool {
	return t == OwnershipPrimary || t == OwnershipSecondary
}

// PermissionEffect represents the effect of a permission grant.
type PermissionEffect string

const (
	// EffectAllow grants the permission.
	EffectAllow PermissionEffect = "allow"
	// EffectDeny denies the permission (overrides allow).
	EffectDeny PermissionEffect = "deny"
)

// IsValid checks if the effect is valid.
func (e PermissionEffect) IsValid() bool {
	return e == EffectAllow || e == EffectDeny
}

// String returns the string representation.
func (e PermissionEffect) String() string {
	return string(e)
}

// ScopeType represents the type of permission scope.
type ScopeType string

const (
	// ScopeAll applies to all resources.
	ScopeAll ScopeType = "all"
	// ScopeOwnedAssets applies only to assets owned by the group.
	ScopeOwnedAssets ScopeType = "owned_assets"
	// ScopeAssetType applies to specific asset types.
	ScopeAssetType ScopeType = "asset_type"
	// ScopeAssetTags applies to assets with specific tags.
	ScopeAssetTags ScopeType = "asset_tags"
	// ScopeSeverity applies to findings with specific severity levels.
	ScopeSeverity ScopeType = "severity"
)

// AllScopeTypes returns all valid scope types.
func AllScopeTypes() []ScopeType {
	return []ScopeType{
		ScopeAll,
		ScopeOwnedAssets,
		ScopeAssetType,
		ScopeAssetTags,
		ScopeSeverity,
	}
}

// IsValid checks if the scope type is valid.
func (s ScopeType) IsValid() bool {
	return slices.Contains(AllScopeTypes(), s)
}

// String returns the string representation.
func (s ScopeType) String() string {
	return string(s)
}

// ScopeValue represents the configuration for a scope.
type ScopeValue struct {
	AssetTypes  []string `json:"asset_types,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	MinSeverity string   `json:"min_severity,omitempty"`
}

// AssignmentConditions represents conditions for auto-assignment rules.
type AssignmentConditions struct {
	AssetTypes      []string `json:"asset_type,omitempty"`
	FilePathPattern string   `json:"file_path_pattern,omitempty"`
	FindingSeverity []string `json:"finding_severity,omitempty"`
	FindingType     []string `json:"finding_type,omitempty"`
	FindingSource   []string `json:"finding_source,omitempty"`
	AssetTags       []string `json:"asset_tags,omitempty"`
}

// AssignmentOptions represents options for assignment rules.
type AssignmentOptions struct {
	NotifyGroup        bool   `json:"notify_group,omitempty"`
	SetFindingPriority string `json:"set_finding_priority,omitempty"`
}
