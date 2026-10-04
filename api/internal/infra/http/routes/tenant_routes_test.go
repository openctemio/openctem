package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
)

// GET /api/v1/tenants/{tenant} was registered in the /api/v1/tenants group,
// but the /api/v1/tenants/{tenant} group mounts a sub-router on that exact
// path and owns it. The request reached that sub-router, which had only
// PATCH and DELETE on "/", and got 405. The UI (tenantEndpoints.get) and the
// docs expect it to return the tenant.

type routeTenantRepo struct {
	tenant.Repository
	t *tenant.Tenant
}

func (r routeTenantRepo) GetBySlug(context.Context, string) (*tenant.Tenant, error)  { return r.t, nil }
func (r routeTenantRepo) GetByID(context.Context, shared.ID) (*tenant.Tenant, error) { return r.t, nil }

type routeMembers struct{ m *tenant.Membership }

func (r routeMembers) GetMembership(context.Context, shared.ID, shared.ID) (*tenant.Membership, error) {
	return r.m, nil
}

const reachedHandler = 299

func TestTenantRoutes_GetTenantIsRouted(t *testing.T) {
	tn, err := tenant.NewTenant("Acme", "acme", shared.NewID().String())
	if err != nil {
		t.Fatal(err)
	}
	u, err := userdom.NewProvisionedLocalUser("owner@acme.test", "Owner")
	if err != nil {
		t.Fatal(err)
	}
	m, err := tenant.NewMembership(u.ID(), tn.ID(), tenant.RoleOwner, nil)
	if err != nil {
		t.Fatal(err)
	}
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), middleware.LocalUserKey, u)))
		})
	}

	router := infrahttp.NewChiRouter()
	registerTenantRoutes(router, &handler.TenantHandler{}, auth, nil, routeTenantRepo{t: tn}, routeMembers{m: m}, nil, nil)
	mux := router.(interface{ Handler() http.Handler }).Handler()

	serve := func(method, path string) (code int) {
		defer func() {
			if recover() != nil {
				code = reachedHandler
			}
		}()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec.Code
	}

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/tenants/acme"},
		{http.MethodGet, "/api/v1/tenants/" + tn.ID().String()},
		{http.MethodPatch, "/api/v1/tenants/acme"},
		{http.MethodDelete, "/api/v1/tenants/acme"},
		{http.MethodGet, "/api/v1/tenants/acme/members"},
	} {
		// The handler answers 4xx with an empty body or panics on its nil
		// service; either way the route resolved. 404/405 is the router.
		if got := serve(tc.method, tc.path); got == http.StatusNotFound || got == http.StatusMethodNotAllowed {
			t.Errorf("%s %s: got %d from the router, want the handler", tc.method, tc.path, got)
		}
	}
}

// The SSO-change approval endpoints are owner only: an administrator or member
// of the organization is refused before the handler runs (the service then
// re-checks ownership in the database).
func TestTenantRoutes_SSOChangeDecisionsAreOwnerOnly(t *testing.T) {
	tn, err := tenant.NewTenant("Acme", "acme", shared.NewID().String())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		role       tenant.Role
		wantHandle bool
	}{
		{tenant.RoleOwner, true},
		{tenant.RoleAdmin, false},
		{tenant.RoleMember, false},
		{tenant.RoleViewer, false},
	} {
		u, err := userdom.NewProvisionedLocalUser("u@acme.test", "U")
		if err != nil {
			t.Fatal(err)
		}
		m, err := tenant.NewMembership(u.ID(), tn.ID(), tc.role, nil)
		if err != nil {
			t.Fatal(err)
		}
		auth := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), middleware.LocalUserKey, u)))
			})
		}
		router := infrahttp.NewChiRouter()
		registerTenantRoutes(router, &handler.TenantHandler{}, auth, nil, routeTenantRepo{t: tn}, routeMembers{m: m}, nil, &handler.SSOChangeHandler{})
		mux := router.(interface{ Handler() http.Handler }).Handler()

		for _, path := range []string{
			"GET /api/v1/tenants/acme/settings/sso/changes",
			"POST /api/v1/tenants/acme/settings/sso/changes/" + shared.NewID().String() + "/approve",
			"POST /api/v1/tenants/acme/settings/sso/changes/" + shared.NewID().String() + "/reject",
		} {
			method, p, _ := strings.Cut(path, " ")
			code := func() (code int) {
				defer func() {
					if recover() != nil {
						code = reachedHandler // the zero handler panics on its nil service
					}
				}()
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, httptest.NewRequest(method, p, nil))
				return rec.Code
			}()
			if tc.wantHandle && code != reachedHandler {
				t.Errorf("%s as %s: got %d, want the handler", path, tc.role, code)
			}
			if !tc.wantHandle && code != http.StatusForbidden {
				t.Errorf("%s as %s: got %d, want 403", path, tc.role, code)
			}
		}
	}
}

// Resetting a member's 2FA is an owner/administrator action: a member or
// viewer is refused by the route before the handler runs.
func TestTenantRoutes_ResetMemberMFAIsAdminOnly(t *testing.T) {
	tn, err := tenant.NewTenant("Acme", "acme", shared.NewID().String())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		role       tenant.Role
		wantHandle bool
	}{
		{tenant.RoleOwner, true},
		{tenant.RoleAdmin, true},
		{tenant.RoleMember, false},
		{tenant.RoleViewer, false},
	} {
		u, err := userdom.NewProvisionedLocalUser("u@acme.test", "U")
		if err != nil {
			t.Fatal(err)
		}
		m, err := tenant.NewMembership(u.ID(), tn.ID(), tc.role, nil)
		if err != nil {
			t.Fatal(err)
		}
		auth := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), middleware.LocalUserKey, u)))
			})
		}
		router := infrahttp.NewChiRouter()
		registerTenantRoutes(router, &handler.TenantHandler{}, auth, nil, routeTenantRepo{t: tn}, routeMembers{m: m}, &handler.LocalAuthHandler{}, nil)
		mux := router.(interface{ Handler() http.Handler }).Handler()

		code := func() (code int) {
			defer func() {
				if recover() != nil {
					code = reachedHandler // the zero handler panics on its nil service
				}
			}()
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/tenants/acme/members/"+shared.NewID().String()+"/reset-2fa", nil))
			return rec.Code
		}()
		if tc.wantHandle && code != reachedHandler {
			t.Errorf("as %s: got %d, want the handler", tc.role, code)
		}
		if !tc.wantHandle && code != http.StatusForbidden {
			t.Errorf("as %s: got %d, want 403", tc.role, code)
		}
	}
}
