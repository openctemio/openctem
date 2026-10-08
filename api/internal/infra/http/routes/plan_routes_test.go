package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/entitlement"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The plan routes register next to the other admin settings (one chi group
// per prefix: a second mount of the same prefix panics at start-up).
func TestPlanAdminRoutesRegister(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("registering the admin routes panicked: %v", r)
		}
	}()
	router := infrahttp.NewChiRouter()
	registerAdminRoutes(router, Handlers{
		AdminAuthMiddleware: middleware.NewAdminAuthMiddleware(nil, logger.NewNop()),
		AdminSignup:         handler.NewAdminSignupHandler(nil, nil, logger.NewNop()),
		AdminOrganization:   &handler.AdminOrganizationHandler{},
		Plan:                handler.NewPlanHandler(entitlement.NewService(nil, nil, nil, nil, nil), nil, logger.NewNop()),
	}, nil, nil)
}

// GET /tenants/{tenant}/plan (Settings > Plan & usage) is for the
// organization's owners and admins; members and viewers are refused before the
// handler runs.
func TestTenantPlanRouteIsAdminOnly(t *testing.T) {
	tn, err := tenant.NewTenant("Acme", "acme", shared.NewID().String())
	if err != nil {
		t.Fatal(err)
	}
	plans := handler.NewPlanHandler(entitlement.NewService(nil, nil, nil, nil, nil), nil, logger.NewNop())
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
				ctx := context.WithValue(r.Context(), middleware.LocalUserKey, u)
				ctx = context.WithValue(ctx, middleware.UserIDKey, u.ID().String())
				next.ServeHTTP(w, r.WithContext(ctx))
			})
		}
		router := infrahttp.NewChiRouter()
		registerTenantRoutes(router, &handler.TenantHandler{}, auth, nil, routeTenantRepo{t: tn}, routeMembers{m: m}, nil, nil, plans)
		mux := router.(interface{ Handler() http.Handler }).Handler()

		handled := func() (reached bool) {
			defer func() {
				if recover() != nil {
					reached = true // the nil repository panics inside the handler
				}
			}()
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/tenants/acme/plan", nil))
			return rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed
		}()
		if handled != tc.wantHandle {
			t.Errorf("%s: handled=%v, want %v", tc.role, handled, tc.wantHandle)
		}
	}
}
