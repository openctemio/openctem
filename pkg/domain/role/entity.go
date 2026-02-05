// Package role provides domain entities for role-based access control.
// Roles define what actions users can perform (permissions).
// Users can have multiple roles, and permissions are the union of all roles.
package role

import (
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
)

// ID represents a unique role identifier.
type ID uuid.UUID

// String returns the string representation of the ID.
func (id ID) String() string {
	return uuid.UUID(id).String()
}

// IsZero checks if the ID is empty/zero.
func (id ID) IsZero() bool {
	return uuid.UUID(id) == uuid.Nil
}

// ParseID parses a string to a role ID.
func ParseID(s string) (ID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return ID{}, err
	}
	return ID(id), nil
}

// NewID generates a new random role ID.
func NewID() ID {
	return ID(uuid.New())
}

// MustParseID parses a string to a role ID, panics on error.
func MustParseID(s string) ID {
	id, err := ParseID(s)
	if err != nil {
		panic(err)
	}
	return id
}

// System role IDs (fixed UUIDs for system roles).
var (
	OwnerRoleID  = MustParseID("00000000-0000-0000-0000-000000000001")
	AdminRoleID  = MustParseID("00000000-0000-0000-0000-000000000002")
	MemberRoleID = MustParseID("00000000-0000-0000-0000-000000000003")
	ViewerRoleID = MustParseID("00000000-0000-0000-0000-000000000004")
)

// Role represents a role entity that defines a set of permissions.
type Role struct {
	id                ID
	tenantID          *ID // nil = system role (global)
	slug              string
	name              string
	description       string
	isSystem          bool
	hierarchyLevel    int
	hasFullDataAccess bool
	permissions       []string
	createdAt         time.Time
	updatedAt         time.Time
	createdBy         *ID
}

// New creates a new custom role for a tenant.
func New(
	tenantID ID,
	slug string,
	name string,
	description string,
	hierarchyLevel int,
	hasFullDataAccess bool,
	permissions []string,
	createdBy ID,
) *Role {
	now := time.Now()
	return &Role{
		id:                NewID(),
		tenantID:          &tenantID,
		slug:              slug,
		name:              name,
		description:       description,
		isSystem:          false, // Custom roles are never system roles
		hierarchyLevel:    hierarchyLevel,
		hasFullDataAccess: hasFullDataAccess,
		permissions:       permissions,
		createdAt:         now,
		updatedAt:         now,
		createdBy:         &createdBy,
	}
}

// Reconstruct creates a role from persistence data.
func Reconstruct(
	id ID,
	tenantID *ID,
	slug string,
	name string,
	description string,
	isSystem bool,
	hierarchyLevel int,
	hasFullDataAccess bool,
	permissions []string,
	createdAt time.Time,
	updatedAt time.Time,
	createdBy *ID,
) *Role {
	return &Role{
		id:                id,
		tenantID:          tenantID,
		slug:              slug,
		name:              name,
		description:       description,
		isSystem:          isSystem,
		hierarchyLevel:    hierarchyLevel,
		hasFullDataAccess: hasFullDataAccess,
		permissions:       permissions,
		createdAt:         createdAt,
		updatedAt:         updatedAt,
		createdBy:         createdBy,
	}
}

// Getters

// ID returns the role ID.
func (r *Role) ID() ID { return r.id }

// TenantID returns the tenant ID (nil for system roles).
func (r *Role) TenantID() *ID { return r.tenantID }

// Slug returns the role slug.
func (r *Role) Slug() string { return r.slug }

// Name returns the role name.
func (r *Role) Name() string { return r.name }

// Description returns the role description.
func (r *Role) Description() string { return r.description }

// IsSystem returns true if this is a system role (immutable).
func (r *Role) IsSystem() bool { return r.isSystem }

// HierarchyLevel returns the hierarchy level.
func (r *Role) HierarchyLevel() int { return r.hierarchyLevel }

// HasFullDataAccess returns true if users with this role can see all data.
func (r *Role) HasFullDataAccess() bool { return r.hasFullDataAccess }

// Permissions returns the list of permission IDs.
func (r *Role) Permissions() []string { return r.permissions }

// CreatedAt returns when the role was created.
func (r *Role) CreatedAt() time.Time { return r.createdAt }

// UpdatedAt returns when the role was last updated.
func (r *Role) UpdatedAt() time.Time { return r.updatedAt }

// CreatedBy returns who created the role.
func (r *Role) CreatedBy() *ID { return r.createdBy }

// IsCustom returns true if this is a tenant-created custom role.
func (r *Role) IsCustom() bool {
	return !r.isSystem && r.tenantID != nil
}

// HasPermission checks if the role has a specific permission.
func (r *Role) HasPermission(permission string) bool {
	return slices.Contains(r.permissions, permission)
}

// PermissionCount returns the number of permissions.
func (r *Role) PermissionCount() int {
	return len(r.permissions)
}

// Update methods (only for custom roles)

// Update updates the role's basic info.
func (r *Role) Update(name, description string, hierarchyLevel int, hasFullDataAccess bool) error {
	if r.isSystem {
		return ErrCannotModifySystemRole
	}
	r.name = name
	r.description = description
	r.hierarchyLevel = hierarchyLevel
	r.hasFullDataAccess = hasFullDataAccess
	r.updatedAt = time.Now()
	return nil
}

// SetPermissions replaces the role's permissions.
func (r *Role) SetPermissions(permissions []string) error {
	if r.isSystem {
		return ErrCannotModifySystemRole
	}
	r.permissions = permissions
	r.updatedAt = time.Now()
	return nil
}

// AddPermission adds a permission to the role.
func (r *Role) AddPermission(permission string) error {
	if r.isSystem {
		return ErrCannotModifySystemRole
	}
	if r.HasPermission(permission) {
		return nil // Already has permission
	}
	r.permissions = append(r.permissions, permission)
	r.updatedAt = time.Now()
	return nil
}

// RemovePermission removes a permission from the role.
func (r *Role) RemovePermission(permission string) error {
	if r.isSystem {
		return ErrCannotModifySystemRole
	}
	newPerms := make([]string, 0, len(r.permissions))
	for _, p := range r.permissions {
		if p != permission {
			newPerms = append(newPerms, p)
		}
	}
	r.permissions = newPerms
	r.updatedAt = time.Now()
	return nil
}

// UserRole represents a role assigned to a user.
type UserRole struct {
	ID         ID
	UserID     ID
	TenantID   ID
	RoleID     ID
	Role       *Role // Populated when fetching with role details
	AssignedAt time.Time
	AssignedBy *ID

	// User details (populated from JOIN when fetching members)
	UserName      string
	UserEmail     string
	UserAvatarURL string
}

// NewUserRole creates a new user role assignment.
func NewUserRole(userID, tenantID, roleID ID, assignedBy *ID) *UserRole {
	return &UserRole{
		ID:         NewID(),
		UserID:     userID,
		TenantID:   tenantID,
		RoleID:     roleID,
		AssignedAt: time.Now(),
		AssignedBy: assignedBy,
	}
}

// Errors
var (
	ErrRoleNotFound           = errors.New("role not found")
	ErrCannotModifySystemRole = errors.New("cannot modify system role")
	ErrCannotDeleteSystemRole = errors.New("cannot delete system role")
	ErrRoleSlugExists         = errors.New("role with this slug already exists")
	ErrRoleInUse              = errors.New("role is assigned to users and cannot be deleted")
	ErrInvalidPermission      = errors.New("invalid permission")
	ErrUserRoleNotFound       = errors.New("user role not found")
	ErrUserRoleExists         = errors.New("user already has this role")
)
