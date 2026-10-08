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
	}, nil)
}

// GET /organization/plan (Settings > Plan & usage) is for the organization's
// owners and admins; the organization comes from the credential. Members and
// viewers are refused before the handler runs.
func TestOrganizationPlanRouteIsAdminOnly(t *testing.T) {
	plans := handler.NewPlanHandler(entitlement.NewService(nil, nil, nil, nil, nil), nil, logger.NewNop())
	for _, tc := range []struct {
		role       string
		admin      bool
		wantHandle bool
	}{
		{"owner", true, true},
		{"admin", true, true},
		{"member", false, false},
		{"viewer", false, false},
	} {
		auth := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := context.WithValue(r.Context(), middleware.UserIDKey, shared.NewID().String())
				ctx = context.WithValue(ctx, middleware.TenantIDKey, shared.NewID().String())
				ctx = context.WithValue(ctx, middleware.RoleKey, tc.role)
				ctx = context.WithValue(ctx, middleware.IsAdminKey, tc.admin)
				next.ServeHTTP(w, r.WithContext(ctx))
			})
		}
		router := infrahttp.NewChiRouter()
		registerOrganizationPlanRoutes(router, plans, auth, nil)
		mux := router.(interface{ Handler() http.Handler }).Handler()

		code := func() (code int) {
			defer func() {
				if recover() != nil {
					code = reachedHandler // the nil repository panics inside the handler
				}
			}()
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/organization/plan", nil))
			return rec.Code
		}()
		if code == http.StatusNotFound || code == http.StatusMethodNotAllowed {
			t.Fatalf("%s: route not registered (%d)", tc.role, code)
		}
		if handled := code != http.StatusForbidden && code != http.StatusUnauthorized; handled != tc.wantHandle {
			t.Errorf("%s: status %d, want handled=%v", tc.role, code, tc.wantHandle)
		}
	}
}
