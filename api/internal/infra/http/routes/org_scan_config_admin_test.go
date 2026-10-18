package routes

// Organization-wide scan configuration (the default scan profile, a profile's
// quality gate, tool enablement and the secret store) is for the owner and
// administrators: a member whose role carries the write permission is still
// refused, so the web console can hide the controls from members.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

func TestOrgScanConfigRoutes_AdminOnly(t *testing.T) {
	saved := []Middleware{csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware,
		permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware, idleReadOnlyMiddleware, dataScopeGuardMiddleware}
	t.Cleanup(func() {
		csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware = saved[0], saved[1], saved[2]
		permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware = saved[3], saved[4], saved[5]
		idleReadOnlyMiddleware, dataScopeGuardMiddleware = saved[6], saved[7]
	})
	csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware = nil, nil, nil
	permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware = nil, nil, nil
	idleReadOnlyMiddleware, dataScopeGuardMiddleware = nil, nil

	asCaller := func(admin bool) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := context.WithValue(r.Context(), middleware.TenantIDKey, "tenant-1")
				ctx = context.WithValue(ctx, middleware.IsAdminKey, admin)
				ctx = context.WithValue(ctx, middleware.PermissionsKey, []string{
					permission.ScanProfilesWrite.String(), permission.TenantToolsWrite.String(), permission.SecretStoreDelete.String(),
				})
				next.ServeHTTP(w, r.WithContext(ctx))
			})
		}
	}
	routes := []string{
		"PUT /api/v1/scan-profiles/p1/quality-gate",
		"POST /api/v1/scan-profiles/p1/set-default",
		"PATCH /api/v1/tools/settings",
		"PATCH /api/v1/tools/t1/settings",
		"DELETE /api/v1/secret-store/s1",
	}
	for _, admin := range []bool{false, true} {
		auth := asCaller(admin)
		router := infrahttp.NewChiRouter()
		registerScanProfileRoutes(router, &handler.ScanProfileHandler{}, auth, nil)
		registerToolRoutes(router, &handler.ToolHandler{}, auth, nil)
		registerSecretStoreRoutes(router, &handler.SecretStoreHandler{}, auth, nil)
		mux := router.(interface{ Handler() http.Handler }).Handler()
		for _, route := range routes {
			method, path, _ := strings.Cut(route, " ")
			code := func() (code int) {
				defer func() {
					if recover() != nil {
						code = reachedHandler // a zero handler panics on its nil service
					}
				}()
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader("{}")))
				return rec.Code
			}()
			switch {
			case code == http.StatusNotFound || code == http.StatusMethodNotAllowed:
				t.Errorf("%s: %d from the router (route not registered)", route, code)
			case !admin && code != http.StatusForbidden:
				t.Errorf("member %s: got %d, want 403", route, code)
			case admin && code == http.StatusForbidden:
				t.Errorf("admin %s: refused with 403", route)
			}
		}
	}
}
