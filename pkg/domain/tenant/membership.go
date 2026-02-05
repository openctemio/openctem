package tenant

import (
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Membership represents a user's membership in a tenant.
// Note: Role is now stored in the user_roles table, not in tenant_members.
// The role field here is populated from v_user_effective_role view on read,
// and used for initial role assignment on create.
type Membership struct {
	id        shared.ID
	userID    shared.ID // Local user ID (references users table)
	tenantID  shared.ID
	role      Role       // Effective role (from user_roles, not tenant_members)
	invitedBy *shared.ID // Local user ID of inviter (nil if founder)
	joinedAt  time.Time
}

// NewMembership creates a new Membership.
func NewMembership(userID, tenantID shared.ID, role Role, invitedBy *shared.ID) (*Membership, error) {
	if userID.IsZero() {
		return nil, fmt.Errorf("%w: userID is required", shared.ErrValidation)
	}
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: tenantID is required", shared.ErrValidation)
	}
	if !role.IsValid() {
		return nil, fmt.Errorf("%w: invalid role", shared.ErrValidation)
	}

	return &Membership{
		id:        shared.NewID(),
		userID:    userID,
		tenantID:  tenantID,
		role:      role,
		invitedBy: invitedBy,
		joinedAt:  time.Now().UTC(),
	}, nil
}

// NewOwnerMembership creates a membership for the tenant owner.
func NewOwnerMembership(userID, tenantID shared.ID) (*Membership, error) {
	return NewMembership(userID, tenantID, RoleOwner, nil)
}

// ReconstituteMembership recreates a Membership from persistence.
func ReconstituteMembership(
	id shared.ID,
	userID shared.ID,
	tenantID shared.ID,
	role Role,
	invitedBy *shared.ID,
	joinedAt time.Time,
) *Membership {
	return &Membership{
		id:        id,
		userID:    userID,
		tenantID:  tenantID,
		role:      role,
		invitedBy: invitedBy,
		joinedAt:  joinedAt,
	}
}

// ID returns the membership ID.
func (m *Membership) ID() shared.ID {
	return m.id
}

// UserID returns the local user ID.
func (m *Membership) UserID() shared.ID {
	return m.userID
}

// TenantID returns the tenant ID.
func (m *Membership) TenantID() shared.ID {
	return m.tenantID
}

// Role returns the member's role.
func (m *Membership) Role() Role {
	return m.role
}

// InvitedBy returns the user ID who invited this member.
func (m *Membership) InvitedBy() *shared.ID {
	return m.invitedBy
}

// JoinedAt returns when the member joined.
func (m *Membership) JoinedAt() time.Time {
	return m.joinedAt
}

// IsOwner checks if this membership has owner role.
func (m *Membership) IsOwner() bool {
	return m.role == RoleOwner
}

// IsAdmin checks if this membership has admin role.
func (m *Membership) IsAdmin() bool {
	return m.role == RoleAdmin
}

// CanWrite checks if this membership has write permissions.
func (m *Membership) CanWrite() bool {
	return m.role.CanWrite()
}

// CanRead checks if this membership has read permissions.
func (m *Membership) CanRead() bool {
	return m.role.CanRead()
}

// UpdateRole updates the member's role.
func (m *Membership) UpdateRole(role Role) error {
	if !role.IsValid() {
		return fmt.Errorf("%w: invalid role", shared.ErrValidation)
	}
	m.role = role
	return nil
}
