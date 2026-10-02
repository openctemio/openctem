package middleware

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/logger"
)

// readAllHandler reports how many bytes it could read and whether the body
// limit tripped.
func readAllHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

func postBody(n int) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(make([]byte, n)))
}

// The route-level limit must REPLACE the global one (it used to nest under it,
// so the 50MB ingest limit never applied past the global 10MB).
func TestBodyLimit_RouteLimitOverridesGlobal(t *testing.T) {
	const global, route = 1 << 10, 4 << 10
	h := BodyLimit(global)(BodyLimit(route)(readAllHandler(t)))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postBody(3<<10)) // > global, < route
	if rec.Code != http.StatusOK {
		t.Fatalf("body under the route limit rejected: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, postBody(5<<10)) // > route
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("body over the route limit accepted: %d", rec.Code)
	}
}

// Routes without a route-level limit keep the global protection.
func TestBodyLimit_GlobalStillAppliesWithoutRouteLimit(t *testing.T) {
	h := BodyLimit(1 << 10)(readAllHandler(t))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postBody(2<<10))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("global body limit not enforced: %d", rec.Code)
	}
}

// A limit cannot be replaced once the body has been (partially) read.
func TestBodyLimit_CannotResetAfterRead(t *testing.T) {
	inner := BodyLimit(1 << 20)(readAllHandler(t))
	h := BodyLimit(1 << 10)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 10)
		_, _ = r.Body.Read(buf)
		inner.ServeHTTP(w, r)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postBody(2<<10))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("limit was widened on a consumed body: %d", rec.Code)
	}
}

func TestTenantConcurrencyLimiter_CapsPerTenant(t *testing.T) {
	l := NewTenantConcurrencyLimiter(2)
	release := make(chan struct{})
	started := make(chan struct{}, 10)
	h := l.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		started <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	req := func(tenant string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/x", nil)
		return r.WithContext(context.WithValue(r.Context(), TenantIDKey, tenant))
	}

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.ServeHTTP(httptest.NewRecorder(), req("t1"))
		}()
	}
	<-started
	<-started

	// Third concurrent request for the same tenant is rejected...
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req("t1"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 over the per-tenant cap, got %d", rec.Code)
	}
	// ...but another tenant is unaffected.
	done := make(chan int)
	go func() {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req("t2"))
		done <- rec.Code
	}()
	<-started
	close(release)
	if code := <-done; code != http.StatusOK {
		t.Fatalf("other tenant throttled: %d", code)
	}
	wg.Wait()

	// Slots are released afterwards.
	rec = httptest.NewRecorder()
	go func() { <-started }()
	h.ServeHTTP(rec, req("t1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("slot not released: %d", rec.Code)
	}
}

func TestTelemetryRateLimiter_MiddlewareKeyed(t *testing.T) {
	rl := NewTelemetryRateLimiter(0.001, 2, time.Minute, logger.NewNop())
	defer rl.Stop()
	key := "sensor-a"
	mw := rl.MiddlewareKeyed(func(*http.Request) string { return key }, "slow down")
	allowed := countAllowed(mw, func(r *http.Request) *http.Request { return r }, 5)
	if allowed != 2 {
		t.Fatalf("expected burst of 2 per key, got %d", allowed)
	}
	key = "sensor-b" // separate bucket
	if got := countAllowed(mw, func(r *http.Request) *http.Request { return r }, 1); got != 1 {
		t.Fatalf("other key throttled")
	}
	key = "" // no key → pass-through
	if got := countAllowed(mw, func(r *http.Request) *http.Request { return r }, 5); got != 5 {
		t.Fatalf("empty key should pass through, got %d", got)
	}
}

func TestRequestID_ValidatesClientValue(t *testing.T) {
	cases := []struct {
		in   string
		keep bool
	}{
		{"", false},
		{"abc-123_DEF.9", true},
		{"550e8400-e29b-41d4-a716-446655440000", true},
		{strings.Repeat("a", 64), true},
		{strings.Repeat("a", 65), false},
		{"bad value", false},
		{"inject\r\nX-Evil: 1", false},
		{"<script>", false},
	}
	for _, tc := range cases {
		var ctxID string
		h := RequestID()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			ctxID = GetRequestID(r.Context())
		}))
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Request-ID", tc.in)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		got := rec.Header().Get("X-Request-ID")
		if tc.keep && got != tc.in {
			t.Errorf("%q: valid id not echoed (got %q)", tc.in, got)
		}
		if !tc.keep && got == tc.in {
			t.Errorf("%q: invalid id echoed", tc.in)
		}
		if !isValidRequestID(got) || ctxID != got {
			t.Errorf("%q: generated id invalid or context mismatch (%q / %q)", tc.in, got, ctxID)
		}
	}
}
