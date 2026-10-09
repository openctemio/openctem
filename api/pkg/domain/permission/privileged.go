package permission

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

// PrivilegedPermissions returns the privileged permissions (a fresh copy).
func PrivilegedPermissions() []Permission {
	return append([]Permission(nil), privilegedPermissions...)
}

// IsPrivilegedRole reports whether a role with these permissions and full
// data access flag is privileged.
func IsPrivilegedRole(perms []string, fullData bool) bool {
	if fullData {
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
