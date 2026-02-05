package group

import "slices"

// GroupType represents the type of a group.
type GroupType string

const (
	// GroupTypeSecurityTeam represents security sub-teams with feature access.
	GroupTypeSecurityTeam GroupType = "security_team"
	// GroupTypeTeam represents dev/owner teams for asset ownership.
	GroupTypeTeam GroupType = "team"
	// GroupTypeDepartment represents organizational units.
	GroupTypeDepartment GroupType = "department"
	// GroupTypeProject represents project-based teams.
	GroupTypeProject GroupType = "project"
	// GroupTypeExternal represents external contractors/vendors.
	GroupTypeExternal GroupType = "external"
)

// AllGroupTypes returns all valid group types.
func AllGroupTypes() []GroupType {
	return []GroupType{
		GroupTypeSecurityTeam,
		GroupTypeTeam,
		GroupTypeDepartment,
		GroupTypeProject,
		GroupTypeExternal,
	}
}

// IsValid checks if the group type is valid.
func (t GroupType) IsValid() bool {
	return slices.Contains(AllGroupTypes(), t)
}

// String returns the string representation.
func (t GroupType) String() string {
	return string(t)
}

// MemberRole represents a user's role within a group.
type MemberRole string

const (
	// MemberRoleOwner can manage group settings and members.
	MemberRoleOwner MemberRole = "owner"
	// MemberRoleLead can add/remove members.
	MemberRoleLead MemberRole = "lead"
	// MemberRoleMember is a standard member.
	MemberRoleMember MemberRole = "member"
)

// AllMemberRoles returns all valid member roles.
func AllMemberRoles() []MemberRole {
	return []MemberRole{
		MemberRoleOwner,
		MemberRoleLead,
		MemberRoleMember,
	}
}

// IsValid checks if the member role is valid.
func (r MemberRole) IsValid() bool {
	return slices.Contains(AllMemberRoles(), r)
}

// String returns the string representation.
func (r MemberRole) String() string {
	return string(r)
}

// CanManageMembers checks if this role can manage group members.
func (r MemberRole) CanManageMembers() bool {
	return r == MemberRoleOwner || r == MemberRoleLead
}

// CanManageSettings checks if this role can manage group settings.
func (r MemberRole) CanManageSettings() bool {
	return r == MemberRoleOwner
}

// GroupSettings represents configurable settings for a group.
type GroupSettings struct {
	AllowSelfJoin   bool `json:"allow_self_join"`
	RequireApproval bool `json:"require_approval"`
	MaxMembers      *int `json:"max_members,omitempty"`
}

// DefaultGroupSettings returns default settings for a new group.
func DefaultGroupSettings() GroupSettings {
	return GroupSettings{
		AllowSelfJoin:   false,
		RequireApproval: true,
		MaxMembers:      nil,
	}
}

// NotificationConfig represents notification settings for a group.
type NotificationConfig struct {
	SlackChannel    string `json:"slack_channel,omitempty"`
	NotifyCritical  bool   `json:"notify_critical"`
	NotifyHigh      bool   `json:"notify_high"`
	NotifyMedium    bool   `json:"notify_medium"`
	NotifyLow       bool   `json:"notify_low"`
	NotifySLAWarn   bool   `json:"notify_sla_warning"`
	NotifySLABreach bool   `json:"notify_sla_breach"`
	WeeklyDigest    bool   `json:"weekly_digest"`
}

// DefaultNotificationConfig returns default notification settings.
func DefaultNotificationConfig() NotificationConfig {
	return NotificationConfig{
		NotifyCritical:  true,
		NotifyHigh:      true,
		NotifyMedium:    false,
		NotifyLow:       false,
		NotifySLAWarn:   true,
		NotifySLABreach: true,
		WeeklyDigest:    true,
	}
}

// ExternalSource represents the source of external sync.
type ExternalSource string

const (
	ExternalSourceGitHub  ExternalSource = "github"
	ExternalSourceGitLab  ExternalSource = "gitlab"
	ExternalSourceAzureAD ExternalSource = "azure_ad"
	ExternalSourceOkta    ExternalSource = "okta"
)

// IsValid checks if the external source is valid.
func (s ExternalSource) IsValid() bool {
	switch s {
	case ExternalSourceGitHub, ExternalSourceGitLab, ExternalSourceAzureAD, ExternalSourceOkta:
		return true
	}
	return false
}

// String returns the string representation.
func (s ExternalSource) String() string {
	return string(s)
}
