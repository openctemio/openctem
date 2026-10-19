package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
)

// Connection tests are limited per tenant: one tenant exhausting its budget
// does not slow another, and the over-limit call never reaches the handler.
func TestTestCredentialsLimiter_PerTenant(t *testing.T) {
	rl := newTestCredentialsLimiter()
	t.Cleanup(rl.Stop)
	calls := 0
	h := rl.TenantMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	send := func(tenant string) int {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/test-credentials", nil)
		r = r.WithContext(context.WithValue(r.Context(), middleware.TenantIDKey, tenant))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	for i := 0; i < 5; i++ {
		if code := send("t1"); code != http.StatusOK {
			t.Fatalf("call %d inside the burst: %d", i, code)
		}
	}
	if code := send("t1"); code != http.StatusTooManyRequests {
		t.Fatalf("6th call in a minute: %d, want 429", code)
	}
	if calls != 5 {
		t.Fatalf("handler ran %d times, want 5", calls)
	}
	if code := send("t2"); code != http.StatusOK {
		t.Fatalf("another tenant was limited: %d", code)
	}
}
