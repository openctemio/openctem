package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	infrahttp "github.com/openctemio/api/internal/infra/http"
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
	userdom "github.com/openctemio/api/pkg/domain/user"
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
	registerTenantRoutes(router, &handler.TenantHandler{}, auth, nil, routeTenantRepo{t: tn}, routeMembers{m: m}, nil)
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
