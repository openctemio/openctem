package routes

// One identity for a platform administrator and an application user (RFC-133),
// over the real route registration:
//
//   - the administrator's account is an ordinary member of an organization:
//     its tenant token carries the tenant role only, and the platform role
//     never authorizes a tenant route (a super admin who is a "member" gets 403
//     on a member-administration route);
//   - /users/me says nothing about the platform role;
//   - the console never accepts the application's token (as a Bearer header or
//     as the console cookie), and the tenant API never accepts a console
//     session token;
//   - a live application session does not open the console: the console needs
//     its own sign-in and second factor (a pending console sign-in reads
//     nothing).

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

func newSingleIdentityHarness(t *testing.T) *chainHarness {
	return newChainHarness(t, func(hs *Handlers, db *postgres.DB, _ *adminconsole.Service) {
		log := logger.NewNop()
		users := tenant.NewUserService(postgres.NewUserRepository(db), log)
		hs.User = handler.NewUserHandler(users, nil, validator.New(), log)
	})
}

// memberToken makes userID a member of tenantID with role and mints the tenant
// token the token exchange would issue for that membership.
func (h *chainHarness) memberToken(userID, email, tenantID, role string) string {
	h.t.Helper()
	h.exec(`INSERT INTO tenant_members (id, user_id, tenant_id, role) VALUES ($1, $2, $3, $4)`,
		uuid.NewString(), userID, tenantID, role)
	tok, err := h.gen.GenerateTenantScopedAccessTokenWithPermissions(userID, email, "IT", uuid.NewString(),
		jwt.TenantMembership{TenantID: tenantID, Role: role}, nil, role == "owner" || role == "admin", 0, "password")
	if err != nil {
		h.t.Fatal(err)
	}
	return tok.AccessToken
}

func (h *chainHarness) send(method, path string, hdr map[string]string, cookies ...*http.Cookie) (int, string) {
	h.t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (c *consoleAdmin) sessionCookie() string {
	c.h.t.Helper()
	u, _ := url.Parse(c.h.srv.URL + "/api/v1/admin/")
	for _, ck := range c.jar.Cookies(u) {
		if ck.Name == middleware.AdminSessionCookie {
			return ck.Value
		}
	}
	c.h.t.Fatal("no console session cookie")
	return ""
}

func TestPlatformAdminSingleIdentity_DB(t *testing.T) {
	h := newSingleIdentityHarness(t)
	tenantID := h.organization(1)

	super := h.newAdmin(admin.AdminRoleSuperAdmin)
	super.verify()
	appToken := h.memberToken(super.userID.String(), super.a.Email(), tenantID, "member")
	bearer := map[string]string{"Authorization": "Bearer " + appToken}

	t.Run("the account is an ordinary member in the app", func(t *testing.T) {
		code, body := h.send(http.MethodGet, "/api/v1/users/me", bearer)
		if code != http.StatusOK {
			t.Fatalf("/users/me with the administrator's app token: %d %s", code, body)
		}
		for _, leak := range []string{"is_platform_admin", "super_admin", "ops_admin", "platform_role"} {
			if strings.Contains(body, leak) {
				t.Fatalf("/users/me must not reveal the platform role (%q): %s", leak, body)
			}
		}
	})

	t.Run("the platform role never authorizes a tenant route", func(t *testing.T) {
		other := uuid.NewString()
		code, body := h.send(http.MethodPatch, "/api/v1/tenants/"+tenantID+"/members/"+other, bearer)
		if code != http.StatusForbidden {
			t.Fatalf("a super admin who is a member changed a member's role: %d %s (want 403)", code, body)
		}
	})

	t.Run("the console refuses the application token", func(t *testing.T) {
		if code, body := h.send(http.MethodGet, "/api/v1/admin/auth/validate", bearer); code != http.StatusUnauthorized {
			t.Fatalf("console with an app Bearer token: %d %s (want 401)", code, body)
		}
		asCookie := &http.Cookie{Name: middleware.AdminSessionCookie, Value: appToken}
		if code, body := h.send(http.MethodGet, "/api/v1/admin/auth/validate", nil, asCookie); code != http.StatusUnauthorized {
			t.Fatalf("console with an app token as its cookie: %d %s (want 401)", code, body)
		}
	})

	t.Run("the tenant API refuses the console session token", func(t *testing.T) {
		consoleToken := super.sessionCookie()
		// The console session itself still works.
		if code, body := super.do(http.MethodGet, "/api/v1/admin/auth/validate", nil, false); code != http.StatusOK {
			t.Fatalf("console validate: %d %s", code, body)
		}
		hdr := map[string]string{"Authorization": "Bearer " + consoleToken}
		if code, body := h.send(http.MethodGet, "/api/v1/users/me", hdr); code != http.StatusUnauthorized {
			t.Fatalf("tenant API with a console session token: %d %s (want 401)", code, body)
		}
		ck := &http.Cookie{Name: middleware.AdminSessionCookie, Value: consoleToken}
		if code, body := h.send(http.MethodGet, "/api/v1/users/me", nil, ck); code != http.StatusUnauthorized {
			t.Fatalf("tenant API with only the console cookie: %d %s (want 401)", code, body)
		}
	})

	t.Run("an app session does not open the console; its second factor is required", func(t *testing.T) {
		pending := h.newAdmin(admin.AdminRoleSuperAdmin) // password step done, no second factor
		_ = h.memberToken(pending.userID.String(), pending.a.Email(), tenantID, "admin")
		if code, body := pending.do(http.MethodGet, "/api/v1/admin/auth/validate", nil, false); code != http.StatusUnauthorized {
			t.Fatalf("console before the second factor: %d %s (want 401)", code, body)
		}
		if code, body := pending.do(http.MethodGet, "/api/v1/admin/audit-logs", nil, false); code != http.StatusUnauthorized && code != http.StatusNotFound {
			t.Fatalf("console data before the second factor: %d %s (want 401)", code, body)
		}
		pending.verify()
		if code, body := pending.do(http.MethodGet, "/api/v1/admin/auth/validate", nil, false); code != http.StatusOK {
			t.Fatalf("console after the second factor: %d %s", code, body)
		}
	})
}
