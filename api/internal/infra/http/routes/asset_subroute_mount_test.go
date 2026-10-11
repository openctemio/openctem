package routes

import (
	"net/http"
	"net/http/httptest"
	"testing"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// The asset-scoped component routes must not capture the one-segment asset
// routes. A group mounted at /api/v1/assets/{id} took /api/v1/assets/stats,
// /tags and /{id} itself and answered 404, so the inventory counts read 0.
func TestComponentRoutes_DoNotCaptureOneSegmentAssetRoutes(t *testing.T) {
	router := infrahttp.NewChiRouter()
	passthrough := func(next http.Handler) http.Handler { return next }
	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }

	router.Group("/api/v1/assets", func(r Router) {
		r.GET("/stats", ok)
		r.GET("/tags", ok)
		r.GET("/{id}", ok)
	})
	registerComponentRoutes(router, handler.NewComponentHandler(nil, nil, validator.New(), logger.NewNop()), passthrough, nil, passthrough)
	mux := router.(interface{ Handler() http.Handler }).Handler()

	for _, path := range []string{
		"/api/v1/assets/stats",
		"/api/v1/assets/tags",
		"/api/v1/assets/01a0f6e2-35a7-7cae-af10-874c1481fe6e",
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusTeapot {
			t.Errorf("GET %s = %d, want the asset route (418)", path, rec.Code)
		}
	}
}
