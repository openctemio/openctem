package permissionset

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/permission"
	"github.com/openctemio/api/pkg/domain/shared"
)

var slugRegex = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// PermissionSet represents a reusable bundle of permissions.
type PermissionSet struct {
	id                shared.ID
	tenantID          *shared.ID // NULL = system template
	name              string
	slug              string
	description       string
	setType           SetType
	parentSetID       *shared.ID
	clonedFromVersion *int
	isActive          bool
	createdAt         time.Time
	updatedAt         time.Time
}

// NewPermissionSet creates a new custom permission set.
func NewPermissionSet(tenantID shared.ID, name, slug, description string) (*PermissionSet, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: tenantID is required for custom permission sets", shared.ErrValidation)
	}
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	if slug == "" {
		return nil, fmt.Errorf("%w: slug is required", shared.ErrValidation)
	}
	if !isValidSlug(slug) {
		return nil, fmt.Errorf("%w: invalid slug format", shared.ErrValidation)
	}

	now := time.Now().UTC()
	return &PermissionSet{
		id:          shared.NewID(),
		tenantID:    &tenantID,
		name:        name,
		slug:        strings.ToLower(slug),
		description: description,
		setType:     SetTypeCustom,
		isActive:    true,
		createdAt:   now,
		updatedAt:   now,
	}, nil
}

// NewExtendedPermissionSet creates a permission set that extends a parent.
func NewExtendedPermissionSet(tenantID shared.ID, name, slug, description string, parentSetID shared.ID) (*PermissionSet, error) {
	ps, err := NewPermissionSet(tenantID, name, slug, description)
	if err != nil {
		return nil, err
	}
	if parentSetID.IsZero() {
		return nil, fmt.Errorf("%w: parentSetID is required for extended permission sets", shared.ErrValidation)
	}
	ps.setType = SetTypeExtended
	ps.parentSetID = &parentSetID
	return ps, nil
}

// NewClonedPermissionSet creates a permission set cloned from a parent.
func NewClonedPermissionSet(tenantID shared.ID, name, slug, description string, parentSetID shared.ID, sourceVersion int) (*PermissionSet, error) {
	ps, err := NewPermissionSet(tenantID, name, slug, description)
	if err != nil {
		return nil, err
	}
	if parentSetID.IsZero() {
		return nil, fmt.Errorf("%w: parentSetID is required for cloned permission sets", shared.ErrValidation)
	}
	ps.setType = SetTypeCloned
	ps.parentSetID = &parentSetID
	ps.clonedFromVersion = &sourceVersion
	return ps, nil
}

// Reconstitute recreates a PermissionSet from persistence.
func Reconstitute(
	id shared.ID,
	tenantID *shared.ID,
	name, slug, description string,
	setType SetType,
	parentSetID *shared.ID,
	clonedFromVersion *int,
	isActive bool,
	createdAt, updatedAt time.Time,
) *PermissionSet {
	return &PermissionSet{
		id:                id,
		tenantID:          tenantID,
		name:              name,
		slug:              slug,
		description:       description,
		setType:           setType,
		parentSetID:       parentSetID,
		clonedFromVersion: clonedFromVersion,
		isActive:          isActive,
		createdAt:         createdAt,
		updatedAt:         updatedAt,
	}
}

// ID returns the permission set ID.
func (ps *PermissionSet) ID() shared.ID {
	return ps.id
}

// TenantID returns the tenant ID (nil for system templates).
func (ps *PermissionSet) TenantID() *shared.ID {
	return ps.tenantID
}

// Name returns the permission set name.
func (ps *PermissionSet) Name() string {
	return ps.name
}

// Slug returns the permission set slug.
func (ps *PermissionSet) Slug() string {
	return ps.slug
}

// Description returns the permission set description.
func (ps *PermissionSet) Description() string {
	return ps.description
}

// SetType returns the type of permission set.
func (ps *PermissionSet) SetType() SetType {
	return ps.setType
}

// ParentSetID returns the parent permission set ID (if any).
func (ps *PermissionSet) ParentSetID() *shared.ID {
	return ps.parentSetID
}

// ClonedFromVersion returns the version this set was cloned from.
func (ps *PermissionSet) ClonedFromVersion() *int {
	return ps.clonedFromVersion
}

// IsActive returns whether the permission set is active.
func (ps *PermissionSet) IsActive() bool {
	return ps.isActive
}

// CreatedAt returns the creation timestamp.
func (ps *PermissionSet) CreatedAt() time.Time {
	return ps.createdAt
}

// UpdatedAt returns the last update timestamp.
func (ps *PermissionSet) UpdatedAt() time.Time {
	return ps.updatedAt
}

// IsSystem checks if this is a system template.
func (ps *PermissionSet) IsSystem() bool {
	return ps.setType.IsSystem()
}

// IsExtended checks if this is an extended set.
func (ps *PermissionSet) IsExtended() bool {
	return ps.setType.IsExtended()
}

// IsCloned checks if this is a cloned set.
func (ps *PermissionSet) IsCloned() bool {
	return ps.setType.IsCloned()
}

// IsCustom checks if this is a custom set.
func (ps *PermissionSet) IsCustom() bool {
	return ps.setType.IsCustom()
}

// HasParent checks if this set has a parent.
func (ps *PermissionSet) HasParent() bool {
	return ps.parentSetID != nil && !ps.parentSetID.IsZero()
}

// UpdateName updates the permission set name.
func (ps *PermissionSet) UpdateName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	ps.name = name
	ps.updatedAt = time.Now().UTC()
	return nil
}

// UpdateDescription updates the permission set description.
func (ps *PermissionSet) UpdateDescription(description string) {
	ps.description = description
	ps.updatedAt = time.Now().UTC()
}

// Activate activates the permission set.
func (ps *PermissionSet) Activate() {
	ps.isActive = true
	ps.updatedAt = time.Now().UTC()
}

// Deactivate deactivates the permission set.
func (ps *PermissionSet) Deactivate() {
	ps.isActive = false
	ps.updatedAt = time.Now().UTC()
}

// CanModify checks if this permission set can be modified.
// System templates cannot be modified by tenants.
func (ps *PermissionSet) CanModify() bool {
	return !ps.IsSystem()
}

func isValidSlug(slug string) bool {
	if len(slug) < 2 || len(slug) > 100 {
		return false
	}
	return slugRegex.MatchString(slug)
}

// Item represents a permission included in a permission set.
type Item struct {
	permissionSetID  shared.ID
	permissionID     string
	modificationType ModificationType
}

// NewItem creates a new permission set item.
func NewItem(permissionSetID shared.ID, permissionID string, modType ModificationType) (*Item, error) {
	if permissionSetID.IsZero() {
		return nil, fmt.Errorf("%w: permissionSetID is required", shared.ErrValidation)
	}
	if permissionID == "" {
		return nil, fmt.Errorf("%w: permissionID is required", shared.ErrValidation)
	}
	if !modType.IsValid() {
		return nil, fmt.Errorf("%w: invalid modification type", shared.ErrValidation)
	}
	return &Item{
		permissionSetID:  permissionSetID,
		permissionID:     permissionID,
		modificationType: modType,
	}, nil
}

// ReconstituteItem recreates an Item from persistence.
func ReconstituteItem(permissionSetID shared.ID, permissionID string, modType ModificationType) *Item {
	return &Item{
		permissionSetID:  permissionSetID,
		permissionID:     permissionID,
		modificationType: modType,
	}
}

// PermissionSetID returns the permission set ID.
func (i *Item) PermissionSetID() shared.ID {
	return i.permissionSetID
}

// PermissionID returns the permission ID.
func (i *Item) PermissionID() string {
	return i.permissionID
}

// ModificationType returns the modification type.
func (i *Item) ModificationType() ModificationType {
	return i.modificationType
}

// IsAdd checks if this is an add modification.
func (i *Item) IsAdd() bool {
	return i.modificationType == ModificationAdd
}

// IsRemove checks if this is a remove modification.
func (i *Item) IsRemove() bool {
	return i.modificationType == ModificationRemove
}

// Version represents a version record for a permission set.
type Version struct {
	permissionSetID shared.ID
	version         int
	changes         VersionChanges
	changedAt       time.Time
	changedBy       *shared.ID
}

// VersionChanges represents the changes in a version.
type VersionChanges struct {
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
	Initial bool     `json:"initial,omitempty"`
}

// NewVersion creates a new version record.
func NewVersion(permissionSetID shared.ID, version int, changes VersionChanges, changedBy *shared.ID) (*Version, error) {
	if permissionSetID.IsZero() {
		return nil, fmt.Errorf("%w: permissionSetID is required", shared.ErrValidation)
	}
	if version < 1 {
		return nil, fmt.Errorf("%w: version must be >= 1", shared.ErrValidation)
	}
	return &Version{
		permissionSetID: permissionSetID,
		version:         version,
		changes:         changes,
		changedAt:       time.Now().UTC(),
		changedBy:       changedBy,
	}, nil
}

// ReconstituteVersion recreates a Version from persistence.
func ReconstituteVersion(
	permissionSetID shared.ID,
	version int,
	changes VersionChanges,
	changedAt time.Time,
	changedBy *shared.ID,
) *Version {
	return &Version{
		permissionSetID: permissionSetID,
		version:         version,
		changes:         changes,
		changedAt:       changedAt,
		changedBy:       changedBy,
	}
}

// PermissionSetID returns the permission set ID.
func (v *Version) PermissionSetID() shared.ID {
	return v.permissionSetID
}

// Version returns the version number.
func (v *Version) Version() int {
	return v.version
}

// Changes returns the changes in this version.
func (v *Version) Changes() VersionChanges {
	return v.changes
}

// ChangedAt returns when this version was created.
func (v *Version) ChangedAt() time.Time {
	return v.changedAt
}

// ChangedBy returns who made this change.
func (v *Version) ChangedBy() *shared.ID {
	return v.changedBy
}

// PermissionSetWithItems represents a permission set with its items.
type PermissionSetWithItems struct {
	PermissionSet *PermissionSet
	Items         []*Item
}

// EffectivePermissions returns the effective permissions for this set.
// For custom/system sets: returns all added permissions.
// For extended sets: caller must resolve with parent permissions.
func (ps *PermissionSetWithItems) EffectivePermissions() []permission.Permission {
	if ps.PermissionSet.IsExtended() {
		// Extended sets need parent resolution
		return nil
	}

	result := make([]permission.Permission, 0, len(ps.Items))
	for _, item := range ps.Items {
		if item.IsAdd() {
			if p, ok := permission.ParsePermission(item.PermissionID()); ok {
				result = append(result, p)
			}
		}
	}
	return result
}
