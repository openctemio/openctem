package group

import (
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Member represents a user's membership in a group.
type Member struct {
	groupID  shared.ID
	userID   shared.ID
	role     MemberRole
	joinedAt time.Time
	addedBy  *shared.ID

	// expiresAt ends the membership (RFC-050 W22); nil means no end.
	expiresAt    *time.Time
	expiryReason string
}

// MaxMembershipDuration is the longest a membership may run with an end date.
const MaxMembershipDuration = 365 * 24 * time.Hour

// MaxExpiryReasonLength bounds the reason stored with an end date.
const MaxExpiryReasonLength = 500

// NewMember creates a new group member.
func NewMember(groupID, userID shared.ID, role MemberRole, addedBy *shared.ID) (*Member, error) {
	if groupID.IsZero() {
		return nil, fmt.Errorf("%w: groupID is required", shared.ErrValidation)
	}
	if userID.IsZero() {
		return nil, fmt.Errorf("%w: userID is required", shared.ErrValidation)
	}
	if !role.IsValid() {
		return nil, fmt.Errorf("%w: invalid member role", shared.ErrValidation)
	}

	return &Member{
		groupID:  groupID,
		userID:   userID,
		role:     role,
		joinedAt: time.Now().UTC(),
		addedBy:  addedBy,
	}, nil
}

// ReconstituteMember recreates a Member from persistence.
func ReconstituteMember(
	groupID shared.ID,
	userID shared.ID,
	role MemberRole,
	joinedAt time.Time,
	addedBy *shared.ID,
) *Member {
	return &Member{
		groupID:  groupID,
		userID:   userID,
		role:     role,
		joinedAt: joinedAt,
		addedBy:  addedBy,
	}
}

// GroupID returns the group ID.
func (m *Member) GroupID() shared.ID {
	return m.groupID
}

// UserID returns the user ID.
func (m *Member) UserID() shared.ID {
	return m.userID
}

// Role returns the member's role in the group.
func (m *Member) Role() MemberRole {
	return m.role
}

// JoinedAt returns when the member joined the group.
func (m *Member) JoinedAt() time.Time {
	return m.joinedAt
}

// AddedBy returns the user ID who added this member.
func (m *Member) AddedBy() *shared.ID {
	return m.addedBy
}

// IsOwner checks if this member is an owner.
func (m *Member) IsOwner() bool {
	return m.role == MemberRoleOwner
}

// IsLead checks if this member is a lead.
func (m *Member) IsLead() bool {
	return m.role == MemberRoleLead
}

// CanManageMembers checks if this member can manage other members.
func (m *Member) CanManageMembers() bool {
	return m.role.CanManageMembers()
}

// CanManageSettings checks if this member can manage group settings.
func (m *Member) CanManageSettings() bool {
	return m.role.CanManageSettings()
}

// ExpiresAt returns when the membership ends (nil: no end).
func (m *Member) ExpiresAt() *time.Time {
	return m.expiresAt
}

// ExpiryReason returns why the membership has an end date.
func (m *Member) ExpiryReason() string {
	return m.expiryReason
}

// RestoreExpiry sets the end date read from persistence, unchecked.
func (m *Member) RestoreExpiry(expiresAt *time.Time, reason string) {
	m.expiresAt = expiresAt
	m.expiryReason = reason
}

// SetExpiry gives the membership an end date, or clears it (nil). An end
// date must lie in the future and at most MaxMembershipDuration from now.
func (m *Member) SetExpiry(expiresAt *time.Time, reason string, now time.Time) error {
	if len(reason) > MaxExpiryReasonLength {
		return fmt.Errorf("%w: expiry reason is too long", shared.ErrValidation)
	}
	if expiresAt == nil {
		m.expiresAt, m.expiryReason = nil, ""
		return nil
	}
	at := expiresAt.UTC()
	if !at.After(now) {
		return fmt.Errorf("%w: expires_at must be in the future", shared.ErrValidation)
	}
	if at.Sub(now) > MaxMembershipDuration {
		return fmt.Errorf("%w: expires_at must be within 365 days", shared.ErrValidation)
	}
	m.expiresAt, m.expiryReason = &at, reason
	return nil
}

// IsExpired reports whether the membership has ended at now.
func (m *Member) IsExpired(now time.Time) bool {
	return m.expiresAt != nil && !m.expiresAt.After(now)
}

// UpdateRole updates the member's role.
func (m *Member) UpdateRole(role MemberRole) error {
	if !role.IsValid() {
		return fmt.Errorf("%w: invalid member role", shared.ErrValidation)
	}
	m.role = role
	return nil
}

// MemberWithUser represents a group member with user details.
type MemberWithUser struct {
	Member      *Member
	Email       string
	Name        string
	AvatarURL   string
	LastLoginAt *time.Time
	AddedByName string // Resolved name of who added this member
}

// MemberStats contains statistics about group members.
type MemberStats struct {
	TotalMembers int            `json:"total_members"`
	RoleCounts   map[string]int `json:"role_counts"`
}
