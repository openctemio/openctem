package permission_test

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// The member role is the baseline for outside people: inviting one as a
// member is not "privileged", but people, roles, keys, settings or full data
// access are.
func TestIsAboveMember(t *testing.T) {
	if permission.IsAboveMember(permission.ToStrings(permission.RolePermissions[tenant.RoleMember]), false) {
		t.Error("the member role is above member")
	}
	if permission.IsAboveMember(permission.ToStrings(permission.RolePermissions[tenant.RoleViewer]), false) {
		t.Error("the viewer role is above member")
	}
	for _, p := range []permission.Permission{permission.MembersInvite, permission.RolesWrite, permission.APIKeysWrite, permission.SettingsWrite} {
		if !permission.IsAboveMember([]string{string(p)}, false) {
			t.Errorf("%s is not above member", p)
		}
	}
	if !permission.IsAboveMember(nil, true) {
		t.Error("full data access is not above member")
	}
}

// Either organization dashboard permission opens organization-wide numbers
// and names, so a role carrying one alone is privileged (owner-only team
// binding, two-factor for outside members).
func TestOrgDashboardPermissionsArePrivileged(t *testing.T) {
	for _, p := range []permission.Permission{permission.DashboardsOrgView, permission.DashboardsOrgManage} {
		perms := []string{string(permission.DashboardRead), string(p)}
		if !permission.IsFullDataGrade(perms, false) {
			t.Errorf("%s is not full-data grade", p)
		}
		if !permission.IsPrivilegedRole(perms, false) {
			t.Errorf("a role with %s is not privileged", p)
		}
		if !permission.IsAboveMember(perms, false) {
			t.Errorf("a role with %s is not above member", p)
		}
	}
}
