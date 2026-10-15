package permission_test

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/role"
)

func systemRoleBySlug(t *testing.T, slug string) permission.SystemRole {
	t.Helper()
	for _, r := range permission.SystemRoles() {
		if r.Slug == slug {
			return r
		}
	}
	t.Fatalf("no system role %q", slug)
	return permission.SystemRole{}
}

// The four team roles nest: everything a viewer may do a member may do, and so
// on up. A grant that breaks the chain (viewer holding something member lacks)
// is a least-privilege bug, as team:assignment_rules:read on viewer was.
func TestSystemRoles_TeamRolesNest(t *testing.T) {
	chain := []string{"viewer", "member", "admin", "owner"}
	for i := 0; i+1 < len(chain); i++ {
		lower, upper := systemRoleBySlug(t, chain[i]), systemRoleBySlug(t, chain[i+1])
		for _, p := range lower.Permissions {
			if !permission.Contains(upper.Permissions, p) {
				t.Errorf("%s holds %s but %s does not", lower.Slug, p, upper.Slug)
			}
		}
	}
}

// The ids are the fixed system role ids the rest of the code compares with.
func TestSystemRoles_IDs(t *testing.T) {
	want := map[string]string{
		"owner":  role.OwnerRoleID.String(),
		"admin":  role.AdminRoleID.String(),
		"member": role.MemberRoleID.String(),
		"viewer": role.ViewerRoleID.String(),
	}
	seen := map[string]bool{}
	for _, r := range permission.SystemRoles() {
		if seen[r.ID] || seen[r.Slug] {
			t.Errorf("duplicate system role %s %s", r.ID, r.Slug)
		}
		seen[r.ID], seen[r.Slug] = true, true
		if id, ok := want[r.Slug]; ok && id != r.ID {
			t.Errorf("system role %s has id %s, want %s", r.Slug, r.ID, id)
		}
		if len(r.Permissions) == 0 {
			t.Errorf("system role %s carries no permission", r.Slug)
		}
	}
	for slug := range want {
		if !seen[slug] {
			t.Errorf("system role %s missing", slug)
		}
	}
}

// Every permission a system role carries is in the catalog, and only the
// owner and admin roles carry admin-only permissions.
func TestSystemRoles_PermissionsInCatalogue(t *testing.T) {
	all := permission.AllPermissions()
	for _, r := range permission.SystemRoles() {
		for _, p := range r.Permissions {
			if !permission.Contains(all, p) {
				t.Errorf("%s carries %s, which is not in the catalog", r.Slug, p)
			}
			if permission.IsAdminOnly(string(p)) && !r.AdminBypass {
				t.Errorf("%s carries admin-only %s", r.Slug, p)
			}
		}
	}
}

// Viewers start every membership; they must not list stored scan credentials.
func TestSystemRoles_ViewerCannotListSecretStore(t *testing.T) {
	v := systemRoleBySlug(t, "viewer")
	for _, p := range []permission.Permission{permission.SecretStoreRead, permission.AssignmentRulesRead} {
		if permission.Contains(v.Permissions, p) {
			t.Errorf("viewer holds %s", p)
		}
	}
}
