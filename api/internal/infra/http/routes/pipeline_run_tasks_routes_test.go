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

// A run's task pages need the same permission as the run read
// (pipelines:read); without it the request never reaches the handler.
func TestPipelineRunTasks_NeedsPipelinesRead(t *testing.T) {
	const path = "/api/v1/pipeline-runs/01a0f6e2-35a7-7cae-af10-874c1481fe6e/tasks"

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
		// A nil service panics once the gate lets the request through.
		registerPipelineRoutes(router, handler.NewPipelineHandler(nil, nil, logger.NewNop()), as, nil, nil, nil)
		mux := router.(interface{ Handler() http.Handler }).Handler()
		defer func() {
			if recover() != nil {
				reachedHandler = true
			}
		}()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code, false
	}

	if code, reached := serve([]string{permission.ScansRead.String()}); reached || code != http.StatusForbidden {
		t.Errorf("scans:read only: code=%d reached=%v, want 403", code, reached)
	}
	if _, reached := serve([]string{permission.PipelinesRead.String()}); !reached {
		t.Error("pipelines:read: did not reach the handler")
	}
}
