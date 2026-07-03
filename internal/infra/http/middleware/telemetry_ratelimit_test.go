package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/logger"
)

// helper: count how many of n sequential requests pass through (not 429),
// given the supplied request context.
func countAllowed(mw func(http.Handler) http.Handler, ctxValue func(*http.Request) *http.Request, n int) int {
	allowed := 0
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for i := 0; i < n; i++ {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/v1/agent/ingest", nil)
		r = ctxValue(r)
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusTooManyRequests {
			allowed++
		}
	}
	return allowed
}

// When the authenticated tenant IS present in context (as AuthenticateSource
// now sets it for agent routes), the limiter must actually enforce: only
// burst requests succeed, the rest get 429.
func TestTelemetryRateLimiter_EnforcesWhenTenantPresent(t *testing.T) {
	rl := NewTelemetryRateLimiter(1, 5, time.Minute, logger.NewNop())
	withTenant := func(r *http.Request) *http.Request {
		return r.WithContext(context.WithValue(r.Context(), TenantIDKey, "tenant-abc"))
	}
	allowed := countAllowed(rl.Middleware(), withTenant, 20)
	// burst=5, rps=1 → far fewer than 20 should pass in a tight loop.
	if allowed > 7 {
		t.Fatalf("expected limiter to throttle a tenant-bound flood, but %d/20 passed", allowed)
	}
	if allowed == 0 {
		t.Fatalf("expected at least the burst to pass, got 0")
	}
}

// Regression guard for the bug this fixes: with NO tenant in context the
// limiter passes through everything. This is precisely why agent routes were
// unprotected before AuthenticateSource began setting TenantIDKey — the agent
// auth never populated the tenant, so every request fell through here.
func TestTelemetryRateLimiter_PassesThroughWhenTenantAbsent(t *testing.T) {
	rl := NewTelemetryRateLimiter(1, 5, time.Minute, logger.NewNop())
	noTenant := func(r *http.Request) *http.Request { return r }
	allowed := countAllowed(rl.Middleware(), noTenant, 20)
	if allowed != 20 {
		t.Fatalf("expected all 20 to pass with no tenant key, got %d", allowed)
	}
}
