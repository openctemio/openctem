package permission

import (
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// Privileged permissions (decisions G1-G12 G3). A role is privileged when it has
// full data access or carries one of these: whoever holds them can recruit
// people, mint or hand out roles, read stored scan credentials, mint API keys
// or reconfigure the organization. Binding a privileged role to a team, or
// changing who is in a team that carries one, is for the owner only, with a
// recent sign-in.
var privilegedPermissions = []Permission{
	MembersInvite, MembersWrite,
	GroupsWrite, GroupsMembers, GroupsAssets,
	RolesWrite, RolesDelete, RolesAssign,
	APIKeysWrite,
	SecretStoreRead, SecretStoreWrite,
	SettingsWrite,
}

// fullDataGrade are permissions treated like full data access: whoever holds
// one sees organization-wide data outside their own scope. Organization
// dashboards show organization-wide numbers and names, so their view
// permission counts as full data for two-factor and for binding a role to a
// team (docs/architecture/dashboards.md). Manage counts too: it opens every
// organization dashboard (the routes and the service accept it for reading).
var fullDataGrade = []Permission{DashboardsOrgView, DashboardsOrgManage}

// IsFullDataGrade reports whether a role with these permissions and full data
// access flag sees organization-wide data: full data access, or a
// permission that counts as such.
func IsFullDataGrade(perms []string, fullData bool) bool {
	if fullData {
		return true
	}
	for _, p := range perms {
		for _, q := range fullDataGrade {
			if p == string(q) {
				return true
			}
		}
	}
	return false
}

// PrivilegedPermissions returns the privileged permissions (a fresh copy).
func PrivilegedPermissions() []Permission {
	return append([]Permission(nil), privilegedPermissions...)
}

// IsPrivilegedRole reports whether a role with these permissions and full
// data access flag is privileged.
func IsPrivilegedRole(perms []string, fullData bool) bool {
	if IsFullDataGrade(perms, fullData) {
		return true
	}
	for _, p := range perms {
		for _, q := range privilegedPermissions {
			if p == string(q) {
				return true
			}
		}
	}
	return false
}

// IsAboveMember reports whether a role with these permissions and full data
// access flag can do more than the built-in member role in a way that matters
// for people outside the organization (RFC-095 §4.2): it sees every asset, or
// carries a privileged permission the member role does not (people, teams,
// roles, API keys, settings). The member role itself is not above member, so
// an outside person invited as a member needs neither the inviter's step-up
// nor two-factor beyond the organization's own policies.
func IsAboveMember(perms []string, fullData bool) bool {
	if IsFullDataGrade(perms, fullData) {
		return true
	}
	member := map[Permission]bool{}
	for _, p := range memberBaseline() {
		member[p] = true
	}
	for _, p := range perms {
		for _, q := range privilegedPermissions {
			if p == string(q) && !member[q] {
				return true
			}
		}
	}
	return false
}

// memberBaseline is the built-in member role's permissions.
func memberBaseline() []Permission { return RolePermissions[tenant.RoleMember] }

// IsApprovePermission reports whether p is an approval-type permission (its
// last segment is "approve"): findings, suppressions, scope, scans, sensors.
func IsApprovePermission(p string) bool {
	return strings.HasSuffix(p, ":approve")
}

// GainsStepUpGrade reports whether moving a role from (oldPerms, oldFull) to
// (newPerms, newFull) adds a privileged or approval permission, or full-data
// grade access, that the role did not carry before. Whoever makes such a
// change, or hands the role to a user who gains it, needs a recent sign-in.
func GainsStepUpGrade(oldPerms []string, oldFull bool, newPerms []string, newFull bool) bool {
	if IsFullDataGrade(newPerms, newFull) && !IsFullDataGrade(oldPerms, oldFull) {
		return true
	}
	had := make(map[string]bool, len(oldPerms))
	for _, p := range oldPerms {
		had[p] = true
	}
	for _, p := range newPerms {
		if had[p] {
			continue
		}
		if IsApprovePermission(p) || IsPrivilegedRole([]string{p}, false) {
			return true
		}
	}
	return false
}

// IsStepUpGradeRole reports whether a role with these permissions is
// privileged or carries an approval permission.
func IsStepUpGradeRole(perms []string, fullData bool) bool {
	return GainsStepUpGrade(nil, false, perms, fullData)
}
