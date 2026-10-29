package routes

// Platform roles over the real route registration and database (RFC-134): a
// read-only administrator who also holds the support role reads only counts
// until the session elevates as support, then reads an organization's
// members, and still cannot create an organization (support does not hold
// it) or elevate above what it holds. validate reports the roles and the
// acting permissions.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformauthz"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestPlatformRolesOverRoutes_DB(t *testing.T) {
	h := newChainHarness(t, func(hs *Handlers, db *postgres.DB, console *adminconsole.Service) {
		hs.AdminAuthMiddleware = middleware.NewAdminAuthMiddleware(console, logger.NewNop()).WithElevation(true).
			WithPlatformRoles(postgres.NewPlatformRoleRepository(db))
	})
	tenantID := h.organization(1)
	staff := h.newAdmin(admin.AdminRoleReadonly)
	staff.verify()
	h.exec(`INSERT INTO platform_role_assignments (admin_id, role_id) SELECT $1, id FROM platform_roles WHERE key = 'support'`, staff.a.ID().String())

	validate := func() handler.ValidateResponse {
		t.Helper()
		code, body := staff.do(http.MethodGet, "/api/v1/admin/auth/validate", nil, false)
		if code != http.StatusOK {
			t.Fatalf("validate: %d %s", code, body)
		}
		var v handler.ValidateResponse
		_ = json.Unmarshal([]byte(body), &v)
		return v
	}
	v := validate()
	if strings.Join(v.Roles, ",") != "platform_viewer,support" {
		t.Fatalf("roles %v", v.Roles)
	}
	has := func(list []string, p platformauthz.Permission) bool {
		for _, x := range list {
			if x == string(p) {
				return true
			}
		}
		return false
	}
	if has(v.Permissions, platformauthz.TenantsMembersRead) || !has(v.MaxPermissions, platformauthz.TenantsMembersRead) {
		t.Fatalf("unelevated: acting %v, max %v", v.Permissions, v.MaxPermissions)
	}

	members := func() string {
		t.Helper()
		code, body := staff.do(http.MethodGet, "/api/v1/admin/tenants/"+tenantID+"/users", nil, false)
		if code != http.StatusOK {
			t.Fatalf("members: %d %s", code, body)
		}
		return body
	}
	if body := members(); !strings.Contains(body, `"redacted":true`) {
		t.Fatalf("unelevated support reads members' details: %s", body)
	}

	// Elevating above what it holds is refused.
	staff.resetReplayGuard()
	for _, role := range []string{"platform_admin", "ops_admin", "operator"} {
		staff.closeStepUpWindow()
		code, body := staff.do(http.MethodPost, "/api/v1/admin/auth/elevate",
			map[string]any{"role": role, "minutes": 15, "reason": "Customer sign-in case 77", "totp_code": staff.freshCode(true)}, true)
		staff.resetReplayGuard()
		if code != http.StatusBadRequest && code != http.StatusUnprocessableEntity {
			t.Fatalf("elevate as %s: %d %s, want a refusal", role, code, body)
		}
	}
	staff.closeStepUpWindow()
	code, body := staff.do(http.MethodPost, "/api/v1/admin/auth/elevate",
		map[string]any{"role": "support", "minutes": 15, "reason": "Customer sign-in case 77", "totp_code": staff.freshCode(true)}, true)
	if code != http.StatusOK {
		t.Fatalf("elevate as support: %d %s", code, body)
	}
	if v := validate(); v.ElevatedAs != "support" || !has(v.Permissions, platformauthz.TenantsMembersRead) || has(v.Permissions, platformauthz.TenantsCreate) {
		t.Fatalf("elevated as support: %+v", v)
	}
	if body := members(); strings.Contains(body, `"redacted":true`) {
		t.Fatalf("elevated support still gets counts only: %s", body)
	}
	staff.autoStepUp = true
	if code, body := staff.do(http.MethodPost, "/api/v1/admin/tenants/", map[string]string{"name": "Nope", "owner_email": "x@example.test"}, true); code != http.StatusForbidden {
		t.Fatalf("support created an organization: %d %s", code, body)
	}
}
