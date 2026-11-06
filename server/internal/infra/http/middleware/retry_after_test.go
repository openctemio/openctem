package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// pinJitter makes retryAfterIntN return pick(n) for the test's duration.
func pinJitter(t *testing.T, pick func(n int) int) {
	t.Helper()
	prev := retryAfterIntN
	retryAfterIntN = pick
	t.Cleanup(func() { retryAfterIntN = prev })
}

func TestJitteredRetryAfter_Bounds(t *testing.T) {
	maxSecs := int(MaxRetryAfter / time.Second)
	for _, tc := range []struct {
		refill   time.Duration
		min, max int
	}{
		{0, 1, 2},
		{-time.Second, 1, 2},
		{100 * time.Millisecond, 1, 2},
		{time.Second, 1, 2},
		{1500 * time.Millisecond, 2, 3},
		{10 * time.Second, 10, 15},
		{120 * time.Second, 120, 180},
		{250 * time.Second, 250, maxSecs},
		{time.Hour, maxSecs, maxSecs},
		{time.Duration(1<<63 - 1), maxSecs, maxSecs},
	} {
		// The lowest and highest draw bracket every possible answer.
		pinJitter(t, func(int) int { return 0 })
		lo := JitteredRetryAfter(tc.refill)
		pinJitter(t, func(n int) int { return n - 1 })
		hi := JitteredRetryAfter(tc.refill)
		if lo != tc.min || hi != tc.max {
			t.Errorf("refill %s: range [%d, %d], want [%d, %d]", tc.refill, lo, hi, tc.min, tc.max)
		}
		if lo < 1 || hi > maxSecs {
			t.Errorf("refill %s: [%d, %d] outside [1, %d]", tc.refill, lo, hi, maxSecs)
		}
	}
}

// With the real random source the answers spread over the jitter range
// instead of all naming the same second.
func TestJitteredRetryAfter_Spreads(t *testing.T) {
	seen := map[int]bool{}
	for range 500 {
		n := JitteredRetryAfter(20 * time.Second)
		if n < 20 || n > 30 {
			t.Fatalf("Retry-After %d outside [20, 30]", n)
		}
		seen[n] = true
	}
	if len(seen) < 5 {
		t.Fatalf("500 draws gave only %d distinct values: not jittered", len(seen))
	}
}

func TestTelemetryRateLimiter_RefillTime(t *testing.T) {
	var nilRL *TelemetryRateLimiter
	if got := nilRL.RefillTime("k"); got != 0 {
		t.Fatalf("nil limiter refill = %s, want 0", got)
	}
	off := NewTelemetryRateLimiter(0, 1, time.Minute, logger.NewNop())
	defer off.Stop()
	if got := off.RefillTime("k"); got != 0 {
		t.Fatalf("disabled limiter refill = %s, want 0", got)
	}

	rl := NewTelemetryRateLimiter(1.0/120.0, 1, time.Minute, logger.NewNop())
	defer rl.Stop()
	if got := rl.RefillTime("k"); got != 0 {
		t.Fatalf("full bucket refill = %s, want 0", got)
	}
	if !rl.Allow("k") {
		t.Fatal("first request refused")
	}
	if got := rl.RefillTime("k"); got < 110*time.Second || got > 120*time.Second {
		t.Fatalf("empty bucket refill = %s, want about 120s (one token every 2 minutes)", got)
	}
	if got := rl.RefillTime("other"); got != 0 {
		t.Fatalf("another key's refill = %s, want 0: buckets are per key", got)
	}

	tiny := NewTelemetryRateLimiter(1e-9, 1, time.Minute, logger.NewNop())
	defer tiny.Stop()
	tiny.Allow("k")
	if got := tiny.RefillTime("k"); got != MaxRetryAfter {
		t.Fatalf("near-zero rate refill = %s, want the %s bound", got, MaxRetryAfter)
	}
}

// A refused sensor is told to come back when its bucket refills (plus
// jitter), not after a constant second: with one token per 2 minutes the
// answer lies in [~120 s, 180 s].
func TestV2Throttle_RetryAfterFollowsTheBucket(t *testing.T) {
	perSensor := NewTelemetryRateLimiter(1.0/120.0, 1, time.Minute, logger.NewNop())
	defer perSensor.Stop()
	h := V2Throttle(nil, perSensor, nil, func(*http.Request) string { return "s1" })(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	req := func() *http.Request {
		r := httptest.NewRequest(http.MethodPut, "/x", nil)
		return r.WithContext(context.WithValue(r.Context(), TenantIDKey, "t1"))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req())
	if rec.Code != 204 {
		t.Fatalf("first: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req())
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second: %d, want 429", rec.Code)
	}
	secs, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	if err != nil || secs < 110 || secs > 180 {
		t.Fatalf("Retry-After %q, want whole seconds in [110, 180]", rec.Header().Get("Retry-After"))
	}
}
