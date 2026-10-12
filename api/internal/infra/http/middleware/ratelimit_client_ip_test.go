package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The per-IP rate limit is keyed on the client IP. If a caller could choose
// that IP with X-Forwarded-For, every request would land in a fresh bucket
// and the limit would never trip.
func TestRateLimit_ForgedForwardedForDoesNotOpenNewBuckets(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxies(nil) })

	newLimited := func(t *testing.T) http.Handler {
		t.Helper()
		rl := NewRateLimiter(&config.RateLimitConfig{
			Enabled: true, RequestsPerSec: 0.001, Burst: 1, CleanupInterval: time.Hour,
		}, logger.NewNop())
		t.Cleanup(rl.Stop)
		return rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	}
	send := func(h http.Handler, remote, xff string) int {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
		req.RemoteAddr = remote
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	t.Run("untrusted peer rotating X-Forwarded-For is limited on its socket address", func(t *testing.T) {
		SetTrustedProxies(httpsec.NewTrustedProxySet([]string{"10.0.0.10"}))
		h := newLimited(t)
		if code := send(h, "203.0.113.9:1111", "1.1.1.1"); code != http.StatusOK {
			t.Fatalf("first request = %d, want 200", code)
		}
		if code := send(h, "203.0.113.9:2222", "2.2.2.2"); code != http.StatusTooManyRequests {
			t.Fatalf("second request with a different forged XFF = %d, want 429", code)
		}
	})

	t.Run("behind an appending trusted proxy the forged left entry is ignored", func(t *testing.T) {
		SetTrustedProxies(httpsec.NewTrustedProxySet([]string{"10.0.0.10"}))
		h := newLimited(t)
		if code := send(h, "10.0.0.10:1111", "1.1.1.1, 198.51.100.9"); code != http.StatusOK {
			t.Fatalf("first request = %d, want 200", code)
		}
		if code := send(h, "10.0.0.10:2222", "2.2.2.2, 198.51.100.9"); code != http.StatusTooManyRequests {
			t.Fatalf("same client, different forged left entry = %d, want 429", code)
		}
		// A genuinely different client behind the same proxy has its own bucket.
		if code := send(h, "10.0.0.10:3333", "198.51.100.10"); code != http.StatusOK {
			t.Fatalf("different real client = %d, want 200", code)
		}
	})
}

func TestTenantKeyFunc(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	ctx := context.WithValue(r.Context(), TenantIDKey, "t1")
	if got := TenantKeyFunc(r.WithContext(ctx)); got != "tenant:t1" {
		t.Fatalf("key = %q", got)
	}
	ctx = context.WithValue(r.Context(), UserIDKey, "u1")
	if got := TenantKeyFunc(r.WithContext(ctx)); got != "user:u1" {
		t.Fatalf("key without tenant = %q", got)
	}
}
