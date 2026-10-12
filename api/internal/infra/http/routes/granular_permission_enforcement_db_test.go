package routes

// Permissions that used to be defined but never checked are now enforced
// (backlog D-4). These DB-gated tests check, against the migrated catalog:
//
//   - every system role (owner, admin, member, viewer) keeps exactly the
//     abilities it had: for each newly gated route, a role passed the old gate
//     if and only if it passes the new one;
//   - a /tenants/{tenant}/... route is decided by the caller's permissions in
//     the PATH tenant, so a custom role without the permission is refused even
//     though its membership would have passed before, and a permission held in
//     another tenant does not count.

import (
	"context"
	"net/http"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/role"
)

// gateChange is one route whose gate gained a permission: before, the route
// needed `before`; now it needs `after`.
type gateChange struct {
	route         string
	before, after []permission.Permission
}

var granularGateChanges = []gateChange{
	{"POST /assets/import/*", []permission.Permission{permission.AssetsWrite}, []permission.Permission{permission.AssetsWrite, permission.AssetsImport}},
	{"POST /assets/{id}/scan", []permission.Permission{permission.AssetsWrite}, []permission.Permission{permission.AssetsWrite, permission.ScansExecute}},
	{"POST /scans/{id}/trigger, /scans/quick", []permission.Permission{permission.ScansWrite}, []permission.Permission{permission.ScansWrite, permission.ScansExecute}},
	{"GET /findings/{id}/ai-triage*", []permission.Permission{permission.FindingsRead}, []permission.Permission{permission.FindingsRead, permission.AITriageRead}},
	{"POST /findings/{id}/ai-triage", []permission.Permission{permission.FindingsWrite}, []permission.Permission{permission.FindingsWrite, permission.AITriageTrigger}},
	{"GET /exposures*", []permission.Permission{permission.FindingsRead}, []permission.Permission{permission.FindingsRead, permission.ExposuresRead}},
	{"POST /exposures, /ingest, ctem-id", []permission.Permission{permission.FindingsWrite}, []permission.Permission{permission.FindingsWrite, permission.ExposuresWrite}},
	{"POST /exposures/{id}/resolve, reactivate", []permission.Permission{permission.FindingsWrite}, []permission.Permission{permission.FindingsWrite, permission.ExposuresTriage}},
	{"POST /exposures/{id}/accept, false-positive", []permission.Permission{permission.FindingsApprove}, []permission.Permission{permission.FindingsApprove, permission.ExposuresTriage}},
	{"DELETE /exposures/{id}", []permission.Permission{permission.FindingsDelete}, []permission.Permission{permission.FindingsDelete, permission.ExposuresDelete}},
	{"GET /integrations/scm", []permission.Permission{permission.IntegrationsRead}, []permission.Permission{permission.IntegrationsRead, permission.SCMConnectionsRead}},
	{"create/update SCM integration", []permission.Permission{permission.IntegrationsManage}, []permission.Permission{permission.IntegrationsManage, permission.SCMConnectionsWrite}},
	{"delete SCM integration", []permission.Permission{permission.IntegrationsManage}, []permission.Permission{permission.IntegrationsManage, permission.SCMConnectionsDelete}},
	{"POST/PUT/DELETE /groups/{id}/assets*", []permission.Permission{permission.GroupsWrite}, []permission.Permission{permission.GroupsWrite, permission.GroupsAssets}},
}

// tenantRouteNeeds lists, per membership role, the permissions the
// /tenants/{tenant}/... routes now also require from the role it holds.
var tenantRouteNeeds = map[string][]permission.Permission{
	// Every member could read the organization, its members and settings.
	"viewer": {permission.TeamRead, permission.MembersRead, permission.SettingsRead},
	"member": {permission.TeamRead, permission.MembersRead, permission.SettingsRead},
	// Administrators also manage members, invitations and settings.
	"admin": {permission.TeamRead, permission.MembersRead, permission.SettingsRead,
		permission.TeamUpdate, permission.MembersWrite, permission.MembersInvite, permission.SettingsWrite},
}

func systemRolePermissions(t *testing.T, h *authzPolicyHarness) map[string][]string {
	t.Helper()
	rows, err := h.db.QueryContext(context.Background(), `
		SELECT r.slug, rp.permission_id FROM roles r
		JOIN role_permissions rp ON rp.role_id = r.id
		WHERE r.tenant_id IS NULL AND r.slug IN ('owner', 'admin', 'member', 'viewer')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var slug, perm string
		if err := rows.Scan(&slug, &perm); err != nil {
			t.Fatal(err)
		}
		out[slug] = append(out[slug], perm)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(out) != 4 {
		t.Fatalf("expected the four system roles, got %v", len(out))
	}
	return out
}

func holdsAll(perms []string, need []permission.Permission) bool {
	for _, p := range need {
		if !slices.Contains(perms, p.String()) {
			return false
		}
	}
	return true
}

func TestGranularPermissions_SystemRolesKeepTheirAbilities_DB(t *testing.T) {
	h := newAuthzPolicyHarness(t)
	perms := systemRolePermissions(t, h)
	for slug, held := range perms {
		for _, c := range granularGateChanges {
			if before, after := holdsAll(held, c.before), holdsAll(held, c.after); before != after {
				t.Errorf("%s: %s passed the old gate=%v but the new gate=%v", slug, c.route, before, after)
			}
		}
		if need, ok := tenantRouteNeeds[slug]; ok && !holdsAll(held, need) {
			t.Errorf("%s lacks a permission the /tenants/{tenant} routes it could use now require: %v", slug, need)
		}
	}
	// The removed permissions are gone from the catalog and every role.
	for _, id := range []string{"compliance:frameworks:write", "compliance:reports:read",
		"findings:policies:read", "findings:policies:write", "findings:policies:delete", "settings:billing:read", "settings:billing:write"} {
		var n int
		if err := h.db.QueryRowContext(context.Background(),
			`SELECT (SELECT COUNT(*) FROM permissions WHERE id = $1) + (SELECT COUNT(*) FROM role_permissions WHERE permission_id = $1)`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s still in the catalog or granted (%d rows)", id, n)
		}
	}
}

// roleRepoChecker answers tenant permission questions from the role tables,
// as the permission cache does in production.
type roleRepoChecker struct{ h *authzPolicyHarness }

func (c roleRepoChecker) HasPermission(ctx context.Context, tenantID, userID, perm string) (bool, error) {
	perms, err := c.h.roles.GetUserPermissions(ctx, role.MustParseID(tenantID), role.MustParseID(userID))
	if err != nil {
		return false, err
	}
	return slices.Contains(perms, perm), nil
}

// customRoleMember gives u exactly one custom role in tenantID holding perms.
func (h *authzPolicyHarness) customRoleMember(u policyUser, tenantID string, perms ...permission.Permission) {
	h.t.Helper()
	roleID := uuid.NewString()
	h.exec(`INSERT INTO roles (id, tenant_id, slug, name, hierarchy_level) VALUES ($1, $2, $3, 'Custom', 30)`,
		roleID, tenantID, "custom-"+roleID[:8])
	for _, p := range perms {
		h.exec(`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)`, roleID, p.String())
	}
	h.exec(`DELETE FROM user_roles WHERE user_id = $1 AND tenant_id = $2`, u.id, tenantID)
	h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, u.id, tenantID, roleID)
	h.t.Cleanup(func() { _, _ = h.db.ExecContext(context.Background(), `DELETE FROM roles WHERE id = $1`, roleID) })
}

func TestTenantRoutes_PathTenantPermission_DB(t *testing.T) {
	h := newAuthzPolicyHarness(t)
	saved := tenantPermissionChecker
	tenantPermissionChecker = roleRepoChecker{h: h}
	t.Cleanup(func() { tenantPermissionChecker = saved })

	tidA, tidB := h.tenant(), h.tenant()
	membersPath := func(tid string) string { return "/api/v1/tenants/" + tid + "/members" }

	// A viewer (system role) reads the member list as before.
	h.expect(h.member(tidA, "viewer"), http.MethodGet, membersPath(tidA), "", http.StatusOK)

	// A custom role without team:members:read is refused, though membership
	// alone used to be enough.
	noRead := h.member(tidA, "viewer")
	h.customRoleMember(noRead, tidA, permission.TeamRead)
	h.expect(noRead, http.MethodGet, membersPath(tidA), "", http.StatusForbidden)

	// With the permission it reads.
	withRead := h.member(tidA, "viewer")
	h.customRoleMember(withRead, tidA, permission.MembersRead)
	h.expect(withRead, http.MethodGet, membersPath(tidA), "", http.StatusOK)

	// A permission held in tenant B does not count in tenant A: the user is a
	// member of both, with members:read only in B.
	both := h.member(tidA, "viewer")
	h.customRoleMember(both, tidA, permission.TeamRead)
	h.exec(`INSERT INTO tenant_members (id, user_id, tenant_id, role) VALUES ($1, $2, $3, 'viewer')`, uuid.NewString(), both.id, tidB)
	h.customRoleMember(both, tidB, permission.MembersRead)
	h.expect(both, http.MethodGet, membersPath(tidA), "", http.StatusForbidden)

	// The owner passes without any role check.
	h.expect(h.member(tidA, "owner"), http.MethodGet, membersPath(tidA), "", http.StatusOK)
}
