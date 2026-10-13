package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// serveScanRoutes mounts the scan routes for a caller; a nil service makes
// the handler panic once the gates let a request through ("reached").
func serveScanRoutes(t *testing.T, admin bool, perms []string, method, path string) (code int, reached bool) {
	t.Helper()
	router := infrahttp.NewChiRouter()
	as := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), middleware.IsAdminKey, admin)
			ctx = context.WithValue(ctx, middleware.PermissionsKey, perms)
			ctx = context.WithValue(ctx, middleware.TenantIDKey, testTenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	registerScanRoutes(router, handler.NewScanHandler(nil, nil, nil, nil, logger.NewNop()), as, nil, nil)
	mux := router.(interface{ Handler() http.Handler }).Handler()
	defer func() {
		if recover() != nil {
			reached = true
		}
	}()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec.Code, false
}

// Taking ownership of a scan is for owners and administrators: a member
// holding every scan permission (or an API key, never an admin) is refused
// before the handler.
func TestScanTakeOwnershipRoute_AdminOnly(t *testing.T) {
	path := "/api/v1/scans/" + testRunID + "/take-ownership"
	all := []string{permission.ScansRead.String(), permission.ScansWrite.String(), permission.ScansExecute.String(), permission.ScansDelete.String()}
	if code, reached := serveScanRoutes(t, false, all, http.MethodPost, path); reached || code != http.StatusForbidden {
		t.Fatalf("member with scans:*: code=%d reached=%v, want 403", code, reached)
	}
	// The handler refuses a caller with no user id (400) before it reads
	// the scan: the gates let the administrator through.
	if code, reached := serveScanRoutes(t, true, all, http.MethodPost, path); !reached && code != http.StatusBadRequest {
		t.Fatalf("administrator: code=%d, want the handler's answer", code)
	}
}
