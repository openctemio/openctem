package permissionset

import "slices"

// SetType represents the type of a permission set.
type SetType string

const (
	// SetTypeSystem represents platform-wide templates (tenant_id = NULL).
	SetTypeSystem SetType = "system"
	// SetTypeExtended inherits from parent, auto-syncs new permissions.
	SetTypeExtended SetType = "extended"
	// SetTypeCloned is an independent copy, manual updates.
	SetTypeCloned SetType = "cloned"
	// SetTypeCustom is built from scratch by tenant.
	SetTypeCustom SetType = "custom"
)

// AllSetTypes returns all valid set types.
func AllSetTypes() []SetType {
	return []SetType{
		SetTypeSystem,
		SetTypeExtended,
		SetTypeCloned,
		SetTypeCustom,
	}
}

// IsValid checks if the set type is valid.
func (t SetType) IsValid() bool {
	return slices.Contains(AllSetTypes(), t)
}

// String returns the string representation.
func (t SetType) String() string {
	return string(t)
}

// IsSystem checks if this is a system template.
func (t SetType) IsSystem() bool {
	return t == SetTypeSystem
}

// IsExtended checks if this is an extended set.
func (t SetType) IsExtended() bool {
	return t == SetTypeExtended
}

// IsCloned checks if this is a cloned set.
func (t SetType) IsCloned() bool {
	return t == SetTypeCloned
}

// IsCustom checks if this is a custom set.
func (t SetType) IsCustom() bool {
	return t == SetTypeCustom
}

// RequiresParent checks if this set type requires a parent.
func (t SetType) RequiresParent() bool {
	return t == SetTypeExtended || t == SetTypeCloned
}

// ModificationType represents the type of permission modification.
type ModificationType string

const (
	// ModificationAdd adds a permission.
	ModificationAdd ModificationType = "add"
	// ModificationRemove removes a permission.
	ModificationRemove ModificationType = "remove"
)

// AllModificationTypes returns all valid modification types.
func AllModificationTypes() []ModificationType {
	return []ModificationType{
		ModificationAdd,
		ModificationRemove,
	}
}

// IsValid checks if the modification type is valid.
func (m ModificationType) IsValid() bool {
	return slices.Contains(AllModificationTypes(), m)
}

// String returns the string representation.
func (m ModificationType) String() string {
	return string(m)
}
