package group

import (
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Member represents a user's membership in a group.
type Member struct {
	groupID  shared.ID
	userID   shared.ID
	role     MemberRole
	joinedAt time.Time
	addedBy  *shared.ID
}

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
}

// MemberStats contains statistics about group members.
type MemberStats struct {
	TotalMembers int            `json:"total_members"`
	RoleCounts   map[string]int `json:"role_counts"`
}
