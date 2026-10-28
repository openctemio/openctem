package routes

// Platform role management over the real routes and database (RFC-134), and
// the separation from the tenant side:
//
//   - only a holder of platform.roles.assign (the owner; the route matrix
//     covers every other role) gives or takes an
//     additional role, never to itself, never a base role; the change is
//     audited and takes effect on the next request;
//   - an account that holds platform roles and is a member of an
//     organization looks like any other member on the tenant API (members,
//     /users/me, audit log): no platform role, flag or key in any answer;
//   - a tenant administrator's token reaches no platform role route.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/app/platformrole"
	"github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformauthz"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

func newRoleManagementHarness(t *testing.T) *chainHarness {
	return newChainHarness(t, func(hs *Handlers, db *postgres.DB, console *adminconsole.Service) {
		log := logger.NewNop()
		roles := postgres.NewPlatformRoleRepository(db)
		hs.AdminAuthMiddleware = middleware.NewAdminAuthMiddleware(console, log).WithPlatformRoles(roles)
		hs.AdminPlatformRole = handler.NewAdminPlatformRoleHandler(
			platformrole.NewService(roles, postgres.NewAdminRepository(db), nil, log), log)
		hs.User = handler.NewUserHandler(tenant.NewUserService(postgres.NewUserRepository(db), log), nil, validator.New(), log)
		hs.AdminUser = handler.NewAdminUserHandler(postgres.NewAdminRepository(db), log)
	})
}

func TestPlatformRoleManagement_DB(t *testing.T) {
	h := newRoleManagementHarness(t)
	owner := h.newAdmin(admin.AdminRoleSuperAdmin)
	owner.verify()
	owner.autoStepUp = true
	staff := h.newAdmin(admin.AdminRoleReadonly)
	staff.verify()

	rolesOf := func(c *consoleAdmin) (roles, max []string) {
		t.Helper()
		code, body := c.do(http.MethodGet, "/api/v1/admin/auth/validate", nil, false)
		if code != http.StatusOK {
			t.Fatalf("validate: %d %s", code, body)
		}
		var v handler.ValidateResponse
		_ = json.Unmarshal([]byte(body), &v)
		return v.Roles, v.MaxPermissions
	}
	if code, body := staff.do(http.MethodGet, "/api/v1/admin/platform-roles/", nil, false); code != http.StatusOK || !strings.Contains(body, `"owners_warning"`) {
		t.Fatalf("any role reads the role catalog: %d %s", code, body)
	}
	if code, _ := staff.do(http.MethodGet, "/api/v1/admin/platform-roles/assignments", nil, false); code != http.StatusForbidden {
		t.Fatalf("the read-only role reads who holds what: %d", code)
	}

	assign := func(c *consoleAdmin, target *consoleAdmin, role string) (int, string) {
		return c.do(http.MethodPost, "/api/v1/admin/users/"+target.a.ID().String()+"/platform-roles",
			map[string]string{"role": role, "reason": "New support engineer, ticket 42"}, true)
	}
	staff.autoStepUp = true
	if code, body := assign(staff, owner, "support"); code != http.StatusForbidden {
		t.Fatalf("a read-only admin gave a role: %d %s", code, body)
	}
	staff.autoStepUp = false
	if code, body := assign(owner, owner, "support"); code != http.StatusForbidden {
		t.Fatalf("self-assignment: %d %s", code, body)
	}
	if code, body := assign(owner, staff, "platform_owner"); code != http.StatusBadRequest {
		t.Fatalf("a base role through the role routes: %d %s", code, body)
	}
	if code, body := assign(owner, staff, "support"); code != http.StatusNoContent {
		t.Fatalf("owner gives support: %d %s", code, body)
	}
	roles, max := rolesOf(staff)
	if strings.Join(roles, ",") != "platform_viewer,support" || !strings.Contains(strings.Join(max, ","), string(platformauthz.UsersSupport)) {
		t.Fatalf("after the grant: roles %v, max %v", roles, max)
	}
	var audited int
	if err := h.db.QueryRow(`SELECT count(*) FROM admin_audit_logs WHERE action = $1 AND admin_id = $2`, platformrole.ActionAssigned, owner.a.ID().String()).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("assignment audit rows: %d %v", audited, err)
	}

	// The tenant side: the owner's and the staff member's accounts are
	// members of an organization; nothing there reveals their platform roles.
	tenantID := h.organization(1)
	for _, c := range []*consoleAdmin{owner, staff} {
		// An authorized tenant user (the organization's owner), so every
		// route answers for real: a 403 body would pass the scan vacuously.
		tok := h.memberToken(c.userID.String(), c.a.Email(), tenantID, "owner")
		for _, path := range []string{"/api/v1/users/me", "/api/v1/tenants/" + tenantID + "/members", "/api/v1/audit-logs"} {
			code, body := h.send(http.MethodGet, path, map[string]string{"Authorization": "Bearer " + tok})
			if code != http.StatusOK {
				t.Fatalf("%s as the organization's owner: %d %s (want 200)", path, code, body)
			}
			for _, leak := range []string{"platform_owner", "platform_viewer", `"support"`, "super_admin", "readonly", "platform.", "is_platform_admin", "platform_role"} {
				if strings.Contains(body, leak) {
					t.Errorf("%s reveals %q to the organization: %s", path, leak, body)
				}
			}
		}
	}
	tenantAdmin := h.tenantToken(tenantID, "owner")
	for _, path := range []string{"/api/v1/admin/platform-roles/", "/api/v1/admin/platform-roles/assignments"} {
		if code, _ := h.send(http.MethodGet, path, map[string]string{"Authorization": "Bearer " + tenantAdmin}); code != http.StatusUnauthorized {
			t.Errorf("a tenant owner's token on %s: %d, want 401", path, code)
		}
	}

	if code, body := owner.do(http.MethodDelete, "/api/v1/admin/users/"+staff.a.ID().String()+"/platform-roles/support",
		map[string]string{"reason": "Moved to another team, ticket 43"}, true); code != http.StatusNoContent {
		t.Fatalf("owner takes support: %d %s", code, body)
	}
	if roles, _ := rolesOf(staff); strings.Join(roles, ",") != "platform_viewer" {
		t.Fatalf("after taking it: %v", roles)
	}
}
