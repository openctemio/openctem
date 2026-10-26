package tenant

import "strings"

// MFAFloor is the platform's lowest two-factor requirement for every
// organization (platform setting auth.mfa). An organization may require more
// (SecuritySettings.MFARequired, MFARequiredForAdmins), never less.
type MFAFloor string

const (
	// MFAFloorNone: the platform requires nothing; organizations decide.
	MFAFloorNone MFAFloor = "none"
	// MFAFloorAdmins: owners, administrators and members with a privileged
	// role (permission.IsPrivilegedRole, by direct or team grant).
	MFAFloorAdmins MFAFloor = "admins"
	// MFAFloorEveryone: every member.
	MFAFloorEveryone MFAFloor = "everyone"
)

// ParseMFAFloor reads a floor name (case-insensitive).
func ParseMFAFloor(s string) (MFAFloor, bool) {
	f := MFAFloor(strings.ToLower(strings.TrimSpace(s)))
	switch f {
	case MFAFloorNone, MFAFloorAdmins, MFAFloorEveryone:
		return f, true
	}
	return "", false
}

// Rank orders the floors: none < admins < everyone.
func (f MFAFloor) Rank() int {
	switch f {
	case MFAFloorAdmins:
		return 1
	case MFAFloorEveryone:
		return 2
	}
	return 0
}

// IsAdminBaseRole reports whether the organization role is owner or admin.
func IsAdminBaseRole(role string) bool {
	switch Role(role) {
	case RoleOwner, RoleAdmin:
		return true
	}
	return false
}

// AppliesTo reports whether the floor covers a member: everyone, or an
// administrator by effective privilege (owner or admin role, or a privileged
// role granted to the member).
func (f MFAFloor) AppliesTo(role string, privileged bool) bool {
	switch f {
	case MFAFloorEveryone:
		return true
	case MFAFloorAdmins:
		return privileged || IsAdminBaseRole(role)
	}
	return false
}

// RequiresMFAByOrganization reports whether the organization's own settings
// require two-factor for a member: everyone, or administrators by effective
// privilege under "2FA for admins" (the base-role-only MFARequiredFor missed
// a member who holds a privileged role).
func (s SecuritySettings) RequiresMFAByOrganization(role string, privileged bool) bool {
	if s.MFARequired {
		return true
	}
	return s.MFARequiredForAdmins && (privileged || IsAdminBaseRole(role))
}

// BelowMFAFloor reports whether the organization's settings ask for less
// than the floor: with floor everyone, 2FA for everyone is off; with floor
// admins, both 2FA for everyone and for admins are off.
func (s SecuritySettings) BelowMFAFloor(f MFAFloor) bool {
	switch f {
	case MFAFloorEveryone:
		return !s.MFARequired
	case MFAFloorAdmins:
		return !s.MFARequired && !s.MFARequiredForAdmins
	}
	return false
}

// ClampToMFAFloor returns the settings as they apply under the floor: the
// floor raises the two flags on read, it never rewrites the stored section.
func (s SecuritySettings) ClampToMFAFloor(f MFAFloor) SecuritySettings {
	switch f {
	case MFAFloorEveryone:
		s.MFARequired = true
	case MFAFloorAdmins:
		s.MFARequiredForAdmins = true
	}
	return s
}
