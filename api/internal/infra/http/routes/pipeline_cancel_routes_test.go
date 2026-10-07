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

// Owner decision D12 (scans redesign): stopping a scan run needs scans:write.
// Scan runs are pipeline runs and are canceled through
// POST /pipeline-runs/{id}/cancel, which asked for pipelines:write only, so
// a custom role with pipelines:write and no scans rights could stop scans.
func TestPipelineRunCancel_NeedsScansWrite(t *testing.T) {
	const path = "/api/v1/pipeline-runs/01a0f6e2-35a7-7cae-af10-874c1481fe6e/cancel"

	serve := func(perms []string) (code int, reachedHandler bool) {
		router := infrahttp.NewChiRouter()
		as := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := context.WithValue(r.Context(), middleware.IsAdminKey, false)
				ctx = context.WithValue(ctx, middleware.PermissionsKey, perms)
				ctx = context.WithValue(ctx, middleware.TenantIDKey, "01a0f6e2-35a7-7cae-af10-874c1481fe6f")
				next.ServeHTTP(w, r.WithContext(ctx))
			})
		}
		// A nil service makes the handler panic once the gate lets the
		// request through, which is how "reached the handler" is observed.
		registerPipelineRoutes(router, handler.NewPipelineHandler(nil, nil, logger.NewNop()), as, nil, nil, nil)
		mux := router.(interface{ Handler() http.Handler }).Handler()
		defer func() {
			if recover() != nil {
				reachedHandler = true
			}
		}()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		return rec.Code, false
	}

	if code, reached := serve([]string{permission.PipelinesWrite.String()}); reached || code != http.StatusForbidden {
		t.Errorf("pipelines:write only: code=%d reached=%v, want 403", code, reached)
	}
	if code, reached := serve([]string{permission.ScansWrite.String()}); reached || code != http.StatusForbidden {
		t.Errorf("scans:write only: code=%d reached=%v, want 403", code, reached)
	}
	if _, reached := serve([]string{permission.PipelinesWrite.String(), permission.ScansWrite.String()}); !reached {
		t.Error("pipelines:write + scans:write: did not reach the handler")
	}
}
