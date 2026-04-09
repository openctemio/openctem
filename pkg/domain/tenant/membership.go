package tenant

import (
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// MemberStatus represents the lifecycle state of a membership.
type MemberStatus string

const (
	MemberStatusActive    MemberStatus = "active"
	MemberStatusSuspended MemberStatus = "suspended"
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

	// Suspension lifecycle fields (added in migration 000109).
	// status defaults to "active". When suspended, suspended_at and
	// suspended_by are set. When reactivated, they're cleared.
	status      MemberStatus
	suspendedAt *time.Time
	suspendedBy *shared.ID
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
		status:    MemberStatusActive,
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
		status:    MemberStatusActive, // default for existing rows
	}
}

// ReconstituteMembershipWithStatus recreates a Membership including
// suspension lifecycle fields from persistence.
func ReconstituteMembershipWithStatus(
	id shared.ID,
	userID shared.ID,
	tenantID shared.ID,
	role Role,
	invitedBy *shared.ID,
	joinedAt time.Time,
	status MemberStatus,
	suspendedAt *time.Time,
	suspendedBy *shared.ID,
) *Membership {
	if status == "" {
		status = MemberStatusActive
	}
	return &Membership{
		id:          id,
		userID:      userID,
		tenantID:    tenantID,
		role:        role,
		invitedBy:   invitedBy,
		joinedAt:    joinedAt,
		status:      status,
		suspendedAt: suspendedAt,
		suspendedBy: suspendedBy,
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

// Status returns the membership lifecycle state.
func (m *Membership) Status() MemberStatus {
	if m.status == "" {
		return MemberStatusActive
	}
	return m.status
}

// IsSuspended returns true if the membership is suspended.
func (m *Membership) IsSuspended() bool {
	return m.status == MemberStatusSuspended
}

// SuspendedAt returns when the membership was suspended (nil if active).
func (m *Membership) SuspendedAt() *time.Time {
	return m.suspendedAt
}

// SuspendedBy returns who suspended the membership (nil if active).
func (m *Membership) SuspendedBy() *shared.ID {
	return m.suspendedBy
}

// Suspend marks the membership as suspended. The caller is responsible
// for revoking sessions and invalidating the permission cache after
// calling this — the domain entity is not aware of infrastructure.
func (m *Membership) Suspend(by shared.ID) error {
	if m.IsOwner() {
		return fmt.Errorf("%w: cannot suspend the tenant owner", shared.ErrValidation)
	}
	if m.IsSuspended() {
		return fmt.Errorf("%w: membership is already suspended", shared.ErrValidation)
	}
	now := time.Now().UTC()
	m.status = MemberStatusSuspended
	m.suspendedAt = &now
	m.suspendedBy = &by
	return nil
}

// Reactivate marks the membership as active again. Clears the
// suspended_at and suspended_by fields.
func (m *Membership) Reactivate() error {
	if !m.IsSuspended() {
		return fmt.Errorf("%w: membership is not suspended", shared.ErrValidation)
	}
	m.status = MemberStatusActive
	m.suspendedAt = nil
	m.suspendedBy = nil
	return nil
}
