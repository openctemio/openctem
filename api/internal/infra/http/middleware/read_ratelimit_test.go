package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestReadEndpointRateLimitConfigFrom(t *testing.T) {
	tests := []struct {
		name    string
		in      config.RateLimitConfig
		wantPer int
		wantCI  time.Duration
	}{
		{"unset keeps default", config.RateLimitConfig{}, DefaultReadRequestsPerMin, time.Minute},
		{"negative keeps default", config.RateLimitConfig{ReadRequestsPerMin: -5}, DefaultReadRequestsPerMin, time.Minute},
		{"override", config.RateLimitConfig{ReadRequestsPerMin: 900, CleanupInterval: 2 * time.Minute}, 900, 2 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ReadEndpointRateLimitConfigFrom(tt.in)
			assert.Equal(t, tt.wantPer, got.ReadRequestsPerMin)
			assert.Equal(t, tt.wantCI, got.CleanupInterval)
		})
	}
}

// The configured budget is what the limiter enforces: N GETs pass, the
// N+1th is rejected, and non-GET requests are never counted.
func TestReadEndpointRateLimiter_EnforcesConfiguredBudget(t *testing.T) {
	cfg := ReadEndpointRateLimitConfigFrom(config.RateLimitConfig{ReadRequestsPerMin: 3})
	rl := NewReadEndpointRateLimiter(cfg, logger.NewNop())
	defer rl.Stop()

	h := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	do := func(method string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/v1/findings", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	for i := 0; i < 3; i++ {
		rec := do(http.MethodGet)
		assert.Equal(t, http.StatusOK, rec.Code, "GET %d should pass", i+1)
		assert.Equal(t, "3", rec.Header().Get("X-RateLimit-Limit"))
	}
	assert.Equal(t, http.StatusOK, do(http.MethodPost).Code, "POST is not read-limited")
	assert.Equal(t, http.StatusTooManyRequests, do(http.MethodGet).Code, "4th GET exceeds budget")
}

// A hard load of a detail page sends about twenty reads at once, and an
// analyst steps through findings every few seconds: six finding pages in a
// burst (126 reads) must pass the default budget. Each user has a bucket of
// their own, so one user's reads never refuse another's, and a refused read
// says when to retry.
func TestReadEndpointRateLimiter_DefaultFitsDetailPagesPerUser(t *testing.T) {
	rl := NewReadEndpointRateLimiter(DefaultReadEndpointRateLimitConfig(), logger.NewNop())
	defer rl.Stop()
	h := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	get := func(user string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/x/participants", nil)
		req.RemoteAddr = "10.0.0.1:1234" // every user behind one address
		req = req.WithContext(context.WithValue(req.Context(), UserIDKey, user))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for i := 0; i < 6*21; i++ {
		assert.Equal(t, http.StatusOK, get("analyst").Code, "read %d of six finding pages", i+1)
	}
	var refused *httptest.ResponseRecorder
	for i := 0; i < DefaultReadRequestsPerMin+10; i++ {
		if rec := get("scraper"); rec.Code == http.StatusTooManyRequests {
			refused = rec
			break
		}
	}
	if assert.NotNil(t, refused, "the budget still ends") {
		assert.Equal(t, "1", refused.Header().Get("Retry-After"))
	}
	assert.Equal(t, http.StatusOK, get("analyst").Code, "another user's empty bucket does not refuse this one")
}
