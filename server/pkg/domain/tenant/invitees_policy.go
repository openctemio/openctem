package tenant

// Who may be invited to an organization (RFC-095 §4.1).

// InviteesPolicy is Security.invitees.
type InviteesPolicy string

const (
	// InviteesAny admits any address (the default).
	InviteesAny InviteesPolicy = "any"
	// InviteesVerifiedDomains admits addresses on the organization's
	// verified domains only.
	InviteesVerifiedDomains InviteesPolicy = "verified_domains"
	// InviteesAllowList admits addresses on the organization's verified
	// domains or on Security.allowed_domains.
	InviteesAllowList InviteesPolicy = "allow_list"
)

// IsValid reports whether p is a known value (empty means the default).
func (p InviteesPolicy) IsValid() bool {
	switch p {
	case "", InviteesAny, InviteesVerifiedDomains, InviteesAllowList:
		return true
	}
	return false
}

// EffectiveInvitees returns the policy in force for these settings: the stored value,
// or for an organization that never set it, allow_list when it has allowed
// domains and any otherwise.
func (s SecuritySettings) EffectiveInvitees() InviteesPolicy {
	if s.Invitees != "" {
		return s.Invitees
	}
	if len(s.AllowedDomains) > 0 {
		return InviteesAllowList
	}
	return InviteesAny
}
