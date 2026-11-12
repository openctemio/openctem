package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The quick scan preview reads the inventory on every call, so it is
// limited per tenant, in a bucket of its own (a burst of previews does not
// use up the quick scan trigger bucket).
func TestQuickScanPreviewMiddleware_LimitsPerTenant(t *testing.T) {
	rl := middleware.NewTriggerRateLimiter(middleware.TriggerRateLimitConfig{QuickScanPreviewsPerMin: 3}, logger.NewNop())
	defer rl.Stop()
	h := rl.QuickScanPreviewMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	call := func(tenant string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/scans/quick/preview", nil)
		req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, tenant))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < 3; i++ {
		if c := call("tenant-a"); c != http.StatusOK {
			t.Fatalf("call %d = %d, want 200", i, c)
		}
	}
	if c := call("tenant-a"); c != http.StatusTooManyRequests {
		t.Errorf("call over the burst = %d, want 429", c)
	}
	if c := call("tenant-b"); c != http.StatusOK {
		t.Errorf("another tenant = %d, want 200", c)
	}
	quick := rl.QuickScanMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans/quick", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, "tenant-a"))
	rec := httptest.NewRecorder()
	quick.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("quick scan trigger after preview limit = %d, want 200", rec.Code)
	}
}
