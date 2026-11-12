package tenant

// Role represents a user's role within a tenant.
type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
	RoleViewer Role = "viewer"
)

// IsValid checks if the role is valid.
func (r Role) IsValid() bool {
	switch r {
	case RoleOwner, RoleAdmin, RoleMember, RoleViewer:
		return true
	}
	return false
}

// String returns the string representation of the role.
func (r Role) String() string {
	return string(r)
}

// CanInvite checks if this role can invite new members.
func (r Role) CanInvite() bool {
	return r == RoleOwner || r == RoleAdmin
}

// CanManageMembers checks if this role can manage (update/remove) members.
func (r Role) CanManageMembers() bool {
	return r == RoleOwner || r == RoleAdmin
}

// CanWrite checks if this role has write permissions.
func (r Role) CanWrite() bool {
	return r == RoleOwner || r == RoleAdmin || r == RoleMember
}

// CanRead checks if this role has read permissions.
func (r Role) CanRead() bool {
	return r.IsValid() // All valid roles can read
}

// CanDelete checks if this role can delete the tenant.
func (r Role) CanDelete() bool {
	return r == RoleOwner
}

// CanManageBilling checks if this role can manage billing.
func (r Role) CanManageBilling() bool {
	return r == RoleOwner
}

// Priority returns the priority of the role (higher = more permissions).
func (r Role) Priority() int {
	switch r {
	case RoleOwner:
		return 4
	case RoleAdmin:
		return 3
	case RoleMember:
		return 2
	case RoleViewer:
		return 1
	default:
		return 0
	}
}

// CanAssignRole checks if this role can assign the target role to others.
func (r Role) CanAssignRole(target Role) bool {
	// Can only assign roles with lower priority
	// Owners can assign any role except owner
	if r == RoleOwner {
		return target != RoleOwner
	}
	// Admins can assign member and viewer
	if r == RoleAdmin {
		return target == RoleMember || target == RoleViewer
	}
	return false
}

// InvitableRoles returns the roles that can be assigned when inviting.
// Note: Owner role cannot be assigned via invitation.
var InvitableRoles = []Role{RoleAdmin, RoleMember, RoleViewer}

// ParseRole parses a string to a Role.
func ParseRole(s string) (Role, bool) {
	r := Role(s)
	return r, r.IsValid()
}
