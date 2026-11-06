package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Support access on the organization side: only an owner grants, and only
// after a recent re-authentication (no step-up checker here: refused); owners
// and admins list and revoke; every member reads the active list; the
// organization comes from the credential.
func TestOrganizationSupportAccessRouteGates(t *testing.T) {
	h := handler.NewSupportAccessHandler(nil, logger.NewNop())
	type caller struct {
		role  string
		admin bool
		perms []string
	}
	owner := caller{"owner", true, nil}
	adm := caller{"admin", true, nil}
	member := caller{"member", false, []string{permission.TeamRead.String()}}
	cases := []struct {
		who        caller
		method     string
		path       string
		wantHandle bool
	}{
		{member, http.MethodGet, "/api/v1/organization/support-access/active", true},
		{member, http.MethodGet, "/api/v1/organization/support-access/grants", false},
		{adm, http.MethodGet, "/api/v1/organization/support-access/grants", true},
		{member, http.MethodPost, "/api/v1/organization/support-access/grants", false},
		{adm, http.MethodPost, "/api/v1/organization/support-access/grants", false},
		// The owner without a recent step-up is refused too.
		{owner, http.MethodPost, "/api/v1/organization/support-access/grants", false},
		{member, http.MethodDelete, "/api/v1/organization/support-access/grants/" + shared.NewID().String(), false},
		{adm, http.MethodDelete, "/api/v1/organization/support-access/grants/" + shared.NewID().String(), true},
		{owner, http.MethodDelete, "/api/v1/organization/support-access/grants/" + shared.NewID().String(), true},
	}
	for _, tc := range cases {
		auth := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := context.WithValue(r.Context(), middleware.UserIDKey, shared.NewID().String())
				ctx = context.WithValue(ctx, middleware.TenantIDKey, shared.NewID().String())
				ctx = context.WithValue(ctx, middleware.RoleKey, tc.who.role)
				ctx = context.WithValue(ctx, middleware.IsAdminKey, tc.who.admin)
				ctx = context.WithValue(ctx, middleware.PermissionsKey, tc.who.perms)
				next.ServeHTTP(w, r.WithContext(ctx))
			})
		}
		router := infrahttp.NewChiRouter()
		registerOrganizationSupportAccessRoutes(router, h, auth, nil)
		mux := router.(interface{ Handler() http.Handler }).Handler()
		code := func() (code int) {
			defer func() {
				if recover() != nil {
					code = reachedHandler // the nil service panics inside the handler
				}
			}()
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
			// The handler itself answers 403 without a synced local user
			// (no user sync here): that means the gates let it through.
			if rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), "session required") {
				return reachedHandler
			}
			return rec.Code
		}()
		if code == http.StatusNotFound || code == http.StatusMethodNotAllowed {
			t.Fatalf("%s %s: route not registered (%d)", tc.method, tc.path, code)
		}
		handled := code != http.StatusForbidden && code != http.StatusUnauthorized
		if handled != tc.wantHandle {
			t.Errorf("%s %s as %s: status %d, want handled=%v", tc.method, tc.path, tc.who.role, code, tc.wantHandle)
		}
	}
}

// Console side: a read-only administrator is refused before any support
// handler runs; opening a session needs the console step-up.
func TestAdminSupportRouteGates(t *testing.T) {
	cases := []struct {
		role       admin.AdminRole
		method     string
		path       string
		wantHandle bool
	}{
		{admin.AdminRoleReadonly, http.MethodGet, "/api/v1/admin/support/grants", false},
		{admin.AdminRoleReadonly, http.MethodGet, "/api/v1/admin/support/sessions/" + shared.NewID().String() + "/findings", false},
		{admin.AdminRoleOpsAdmin, http.MethodGet, "/api/v1/admin/support/grants", true},
		{admin.AdminRoleOpsAdmin, http.MethodGet, "/api/v1/admin/support/sessions/" + shared.NewID().String() + "/overview", true},
		// No step-up confirmer wired: opening a session is refused.
		{admin.AdminRoleOpsAdmin, http.MethodPost, "/api/v1/admin/support/grants/" + shared.NewID().String() + "/sessions", false},
	}
	for _, tc := range cases {
		router := infrahttp.NewChiRouter()
		registerAdminRoutes(router, Handlers{
			AdminAuthMiddleware: middleware.NewAdminAuthMiddleware(fixedAdminSessions{role: tc.role}, logger.NewNop()),
			AdminSupport:        handler.NewAdminSupportHandler(nil, logger.NewNop()),
		}, nil)
		mux := router.(interface{ Handler() http.Handler }).Handler()
		code := func() (code int) {
			defer func() {
				if recover() != nil {
					code = reachedHandler
				}
			}()
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.AddCookie(&http.Cookie{Name: middleware.AdminSessionCookie, Value: "tok"})
			req.AddCookie(&http.Cookie{Name: middleware.AdminCSRFCookie, Value: "csrf"})
			req.Header.Set(middleware.CSRFHeaderName, middleware.AdminCSRFToken("tok"))
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			return rec.Code
		}()
		if code == http.StatusNotFound || code == http.StatusMethodNotAllowed {
			t.Fatalf("%s %s: route not registered (%d)", tc.method, tc.path, code)
		}
		handled := code != http.StatusForbidden && code != http.StatusUnauthorized && code != http.StatusServiceUnavailable
		if handled != tc.wantHandle {
			t.Errorf("%s %s as %s: status %d, want handled=%v", tc.method, tc.path, tc.role, code, tc.wantHandle)
		}
	}
}

type fixedAdminSessions struct{ role admin.AdminRole }

func (f fixedAdminSessions) Authenticate(ctx context.Context, token string) (*admin.AdminUser, error) {
	a, _, err := f.AuthenticateSession(ctx, token)
	return a, err
}

func (f fixedAdminSessions) AuthenticateSession(_ context.Context, token string) (*admin.AdminUser, *admin.Session, error) {
	if token != "tok" {
		return nil, nil, admin.ErrSessionNotFound
	}
	a := admin.Reconstitute(shared.NewID(), "s@example.com", "S", f.role, true, nil, nil, "", 0, nil, nil, "", time.Now(), nil, time.Now())
	return a, &admin.Session{ID: shared.NewID(), AdminID: a.ID(), MFAVerified: true}, nil
}
