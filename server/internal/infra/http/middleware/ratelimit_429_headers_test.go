package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	mcpoauthapp "github.com/openctemio/openctem/api/internal/app/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// requireRateLimitHeaders checks a 429 carries Retry-After and both header
// families with consistent values.
func requireRateLimitHeaders(t *testing.T, rec *httptest.ResponseRecorder, wantLimit int) {
	t.Helper()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429", rec.Code)
	}
	ra, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	if err != nil || ra < 1 {
		t.Fatalf("Retry-After = %q, want a positive number of seconds", rec.Header().Get("Retry-After"))
	}
	for _, p := range []string{"X-RateLimit-", "RateLimit-"} {
		if got := rec.Header().Get(p + "Limit"); got != strconv.Itoa(wantLimit) {
			t.Errorf("%sLimit = %q, want %d", p, got, wantLimit)
		}
		if got := rec.Header().Get(p + "Remaining"); got != "0" {
			t.Errorf("%sRemaining = %q, want 0", p, got)
		}
		if rec.Header().Get(p+"Reset") == "" {
			t.Errorf("%sReset missing", p)
		}
	}
	// RateLimit-Reset is seconds from now, X-RateLimit-Reset a Unix time.
	secs, err := strconv.Atoi(rec.Header().Get("RateLimit-Reset"))
	if err != nil || secs < 0 || secs > 3600 {
		t.Errorf("RateLimit-Reset = %q, want seconds within the hour", rec.Header().Get("RateLimit-Reset"))
	}
	unix, err := strconv.ParseInt(rec.Header().Get("X-RateLimit-Reset"), 10, 64)
	if err != nil || unix < time.Now().Add(-time.Minute).Unix() {
		t.Errorf("X-RateLimit-Reset = %q, want a Unix timestamp", rec.Header().Get("X-RateLimit-Reset"))
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("429 body is not the JSON envelope")
	}
}

func TestAPIKeyAuth_429CarriesRetryAfterAndRateLimitHeaders(t *testing.T) {
	key := newTestKey(shared.NewID(), []string{"mcp:read"})
	key.SetRateLimit(3)
	h := APIKeyAuth(&fakeAuthenticator{key: key}, logger.NewNop())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	var rec *httptest.ResponseRecorder
	for i := 0; i < 4; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", nil)
		req.Header.Set("Authorization", "Bearer oct_secret123")
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
	}
	requireRateLimitHeaders(t, rec, 3)
}

type fakeMCPTokens struct{}

func (fakeMCPTokens) AuthenticateAccessToken(context.Context, string, string, mcpoauthapp.DPoPRequest) (*mcpoauthapp.Principal, error) {
	return &mcpoauthapp.Principal{GrantID: "grant-429", TenantID: shared.NewID().String(), UserID: shared.NewID().String()}, nil
}

func TestMCPCredentialAuth_429CarriesRetryAfterAndRateLimitHeaders(t *testing.T) {
	noKeys := func(next http.Handler) http.Handler { return next }
	h := MCPCredentialAuth(noKeys, fakeMCPTokens{}, logger.NewNop())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	var rec *httptest.ResponseRecorder
	for i := 0; i < apiKeyBurst+1; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", nil)
		req.Header.Set("Authorization", "Bearer "+mcpoauth.AccessTokenPrefix+"abc")
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if i < apiKeyBurst && rec.Code != http.StatusOK {
			t.Fatalf("request %d refused early: %d", i, rec.Code)
		}
	}
	requireRateLimitHeaders(t, rec, apiKeyBurst)
}

func TestSetRateLimitHeaders_BothFamilies(t *testing.T) {
	rec := httptest.NewRecorder()
	setRateLimitHeaders(rec, 100, 7, time.Now().Add(30*time.Second))
	if rec.Header().Get("RateLimit-Limit") != "100" || rec.Header().Get("X-RateLimit-Limit") != "100" ||
		rec.Header().Get("RateLimit-Remaining") != "7" || rec.Header().Get("X-RateLimit-Remaining") != "7" {
		t.Fatalf("headers: %v", rec.Header())
	}
	if s, _ := strconv.Atoi(rec.Header().Get("RateLimit-Reset")); s < 29 || s > 31 {
		t.Fatalf("RateLimit-Reset = %q", rec.Header().Get("RateLimit-Reset"))
	}
	setRateLimitRemaining(rec, 0)
	if rec.Header().Get("RateLimit-Remaining") != "0" || rec.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Fatalf("remaining not overridden: %v", rec.Header())
	}
}
