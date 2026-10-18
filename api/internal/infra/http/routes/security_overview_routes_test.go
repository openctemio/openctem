package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/securityoverview"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// reachedPanic is returned when the handler ran and failed on its nil
// service: the gates let the request through.
const reachedPanic = -1

func serveWith(t *testing.T, mount func(router infrahttp.Router, auth Middleware), path string, admin bool, perms []string) (code int) {
	t.Helper()
	defer func() {
		if recover() != nil {
			code = reachedPanic
		}
	}()
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), middleware.UserIDKey, shared.NewID().String())
			ctx = context.WithValue(ctx, middleware.TenantIDKey, shared.NewID().String())
			ctx = context.WithValue(ctx, middleware.IsAdminKey, admin)
			ctx = context.WithValue(ctx, middleware.PermissionsKey, perms)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	router := infrahttp.NewChiRouter()
	mount(router, auth)
	mux := router.(interface{ Handler() http.Handler }).Handler()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code
}

// GET /organization/security-overview is for owners and administrators with
// settings:read; members and viewers are refused before the handler runs.
func TestOrganizationSecurityOverviewRouteIsAdminOnly(t *testing.T) {
	h := handler.NewSecurityOverviewHandler(securityoverview.NewService(nil, nil), logger.NewNop())
	mount := func(router infrahttp.Router, auth Middleware) {
		registerOrganizationSecurityOverviewRoutes(router, h, auth, nil)
	}
	const path = "/api/v1/organization/security-overview"
	for _, tc := range []struct {
		name  string
		admin bool
		perms []string
		want  int
	}{
		{"admin", true, nil, http.StatusOK},
		{"member holding settings:read", false, []string{"settings:read"}, http.StatusForbidden},
		{"member", false, nil, http.StatusForbidden},
	} {
		if got := serveWith(t, mount, path, tc.admin, tc.perms); got != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, got, tc.want)
		}
	}
}

// GET /audit-logs/export has the gate of the list: audit:read.
func TestAuditExportRouteNeedsAuditRead(t *testing.T) {
	h := handler.NewAuditHandler(nil, nil, logger.NewNop())
	mount := func(router infrahttp.Router, auth Middleware) { registerAuditRoutes(router, h, auth, nil) }
	const path = "/api/v1/audit-logs/export"
	if got := serveWith(t, mount, path, false, []string{"findings:read"}); got != http.StatusForbidden {
		t.Errorf("without audit:read: status %d, want 403", got)
	}
	// An administrator passes the gate and reaches the handler (which fails
	// on its nil service here).
	if got := serveWith(t, mount, path, true, nil); got == http.StatusForbidden || got == http.StatusNotFound || got == http.StatusMethodNotAllowed {
		t.Errorf("admin: status %d, want the handler to be reached", got)
	}
}
