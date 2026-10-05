package permission

// Admin-only permissions (owner decision 2026-10-02, "sensors and sensor keys
// are admin only"; settings decision B1, 2026-10-04).
//
// Only the system owner and admin roles carry these. A custom role may never
// carry them, whoever creates or edits it: the role service refuses them and a
// database trigger (migration 001012) refuses a role_permissions row that
// would put one on a custom role.
//
// Each of them hands out, invalidates or reconfigures a sensor credential or
// the sensor fleet (create a sensor, rotate or revoke its key, activate or
// deactivate it, change the content or result policy, accept quarantined
// results, manage scan zones). Reading sensors, zones and commands, and
// queueing commands, stay available to custom roles, as they are to members.
var adminOnlyPermissions = []Permission{
	SensorsWrite,
	SensorsDelete,
	CommandsDelete,
	ScanZonesWrite,
	ScanZonesDelete,
}

// AdminOnlyPermissions returns the permissions that only the system owner and
// admin roles may carry (a fresh copy).
func AdminOnlyPermissions() []Permission {
	out := make([]Permission, len(adminOnlyPermissions))
	copy(out, adminOnlyPermissions)
	return out
}

// IsAdminOnly reports whether p may be carried only by the system owner and
// admin roles.
func IsAdminOnly(p string) bool {
	for _, a := range adminOnlyPermissions {
		if string(a) == p {
			return true
		}
	}
	return false
}
