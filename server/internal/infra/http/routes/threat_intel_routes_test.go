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
	"github.com/openctemio/openctem/api/pkg/logger"
)

// EPSS and CISA KEV sync is platform-wide: one organization's administrator
// could switch it off (or trigger it) for every organization. The tenant
// plane has no write route (405); the operator controls live under
// /api/v1/admin.
func TestThreatIntelRoutes_TenantCannotChangeFeedSync(t *testing.T) {
	router := infrahttp.NewChiRouter()
	asTenantAdmin := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), middleware.IsAdminKey, true)
			ctx = context.WithValue(ctx, middleware.TenantIDKey, "01a0f6e2-35a7-7cae-af10-874c1481fe6e")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	registerThreatIntelRoutes(router, handler.NewThreatIntelHandler(nil, nil, logger.NewNop()), asTenantAdmin, nil)
	mux := router.(interface{ Handler() http.Handler }).Handler()

	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/threat-intel/sync", `{"source":"kev"}`},
		{http.MethodPatch, "/api/v1/threat-intel/sync/epss", `{"enabled":false}`},
	} {
		func() {
			defer func() {
				if recover() != nil {
					t.Errorf("%s %s reached the sync handler", tc.method, tc.path)
				}
			}()
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s: got %d, want 405", tc.method, tc.path, rec.Code)
			}
		}()
	}
}
