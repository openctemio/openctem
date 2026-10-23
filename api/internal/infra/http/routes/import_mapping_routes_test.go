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
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// importMappingMux registers the import mapping routes behind a stand-in
// authenticator: the organization and permissions travel in test headers.
// The handler has no service, so a request the gates let through either
// panics or answers from the handler; only a gate answers 403 or 429.
func importMappingMux(t *testing.T) http.Handler {
	t.Helper()
	saved := []Middleware{csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware,
		permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware}
	t.Cleanup(func() {
		csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware = saved[0], saved[1], saved[2]
		permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware = saved[3], saved[4], saved[5]
	})
	csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware = nil, nil, nil
	permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware = nil, nil, nil
	withStepUpChecker(t, alwaysSteppedUp{})
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), middleware.IsAdminKey, false)
			ctx = context.WithValue(ctx, middleware.UserIDKey, "u1")
			ctx = context.WithValue(ctx, middleware.SessionIDKey, "s1")
			ctx = context.WithValue(ctx, middleware.TenantIDKey, r.Header.Get("X-Test-Tenant"))
			ctx = context.WithValue(ctx, middleware.PermissionsKey, strings.Split(r.Header.Get("X-Test-Perms"), ","))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	router := infrahttp.NewChiRouter()
	registerImportMappingRoutes(router, handler.NewImportMappingHandler(nil, nil, logger.NewNop()), auth, nil)
	return router.(interface{ Handler() http.Handler }).Handler()
}

func serveImportMapping(mux http.Handler, tenant string, perms []string, method, path string) (code int) {
	defer func() {
		if recover() != nil {
			code = reachedHandler
		}
	}()
	req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Tenant", tenant)
	req.Header.Set("X-Test-Perms", strings.Join(perms, ","))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Code
}

// Reads need integrations:read or assets:import (an uploader picks a
// mapping); writes, verify and preview need integrations:manage.
func TestImportMappingRoutes_Permissions(t *testing.T) {
	mux := importMappingMux(t)
	tenant := shared.NewID().String()
	id := shared.NewID().String()
	reads := []string{"GET /api/v1/import-mappings", "GET /api/v1/import-mappings/templates",
		"GET /api/v1/import-mappings/" + id, "GET /api/v1/import-mappings/" + id + "/versions/1"}
	writes := []string{"POST /api/v1/import-mappings", "POST /api/v1/import-mappings/verify",
		"POST /api/v1/import-mappings/preview", "PATCH /api/v1/import-mappings/" + id,
		"DELETE /api/v1/import-mappings/" + id, "POST /api/v1/import-mappings/" + id + "/versions"}
	importer := []string{permission.AssetsImport.String()}
	reader := []string{permission.IntegrationsRead.String()}
	manager := []string{permission.IntegrationsManage.String()}
	unrelated := []string{permission.FindingsRead.String()}
	for _, route := range reads {
		method, path, _ := strings.Cut(route, " ")
		for _, perms := range [][]string{importer, reader} {
			if code := serveImportMapping(mux, tenant, perms, method, path); code == http.StatusForbidden {
				t.Errorf("%s with %v: refused", route, perms)
			}
		}
		if code := serveImportMapping(mux, tenant, unrelated, method, path); code != http.StatusForbidden {
			t.Errorf("%s with %v: %d, want 403", route, unrelated, code)
		}
	}
	for _, route := range writes {
		method, path, _ := strings.Cut(route, " ")
		for _, perms := range [][]string{importer, reader} {
			if code := serveImportMapping(mux, tenant, perms, method, path); code != http.StatusForbidden {
				t.Errorf("%s with %v: %d, want 403", route, perms, code)
			}
		}
		if code := serveImportMapping(mux, shared.NewID().String(), manager, method, path); code == http.StatusForbidden || code == http.StatusTooManyRequests {
			t.Errorf("%s with integrations:manage: refused with %d", route, code)
		}
	}
}

// A preview parses up to 5 MiB of hostile input: it is limited per
// organization (burst 5), across its members, and another organization
// keeps its own budget.
func TestImportMappingRoutes_PreviewRateLimitedPerOrganization(t *testing.T) {
	mux := importMappingMux(t)
	manager := []string{permission.IntegrationsManage.String()}
	tenant := shared.NewID().String()
	limited := false
	for i := 0; i < 10; i++ {
		if serveImportMapping(mux, tenant, manager, http.MethodPost, "/api/v1/import-mappings/preview") == http.StatusTooManyRequests {
			limited = true
			if i < 5 {
				t.Fatalf("limited after %d previews, want a burst of 5", i)
			}
			break
		}
	}
	if !limited {
		t.Fatal("10 previews in a row were not rate limited")
	}
	if code := serveImportMapping(mux, shared.NewID().String(), manager, http.MethodPost, "/api/v1/import-mappings/preview"); code == http.StatusTooManyRequests {
		t.Fatal("another organization was limited by the first one's previews")
	}
	// Saving is not limited by previews.
	if code := serveImportMapping(mux, tenant, manager, http.MethodPost, "/api/v1/import-mappings/verify"); code == http.StatusTooManyRequests {
		t.Fatal("verify shares the preview budget")
	}
}
