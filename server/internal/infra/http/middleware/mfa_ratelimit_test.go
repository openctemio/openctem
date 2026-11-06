package middleware_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
)

// The second login step used to share the 5-per-minute per-IP login bucket,
// so a couple of sign-ins and one mistyped code got the correct code a 429.
// It now has its own bucket, keyed by the challenge, with a looser per-IP
// ceiling. Guessing stays bounded by the challenge's attempt cap and the
// per-user lockout, which the service enforces.

func mfaPost(token string) *http.Request {
	body := `{"mfa_token":"` + token + `","code":"123456"}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "198.51.100.7:4711"
	return r
}

func loginPost() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{}`))
	r.RemoteAddr = "198.51.100.7:4711"
	return r
}

func newAuthRL(t *testing.T, cfg middleware.AuthRateLimitConfig) *middleware.AuthRateLimiter {
	t.Helper()
	rl := middleware.NewAuthRateLimiter(cfg, nil)
	t.Cleanup(rl.Stop)
	return rl
}

func TestMFARateLimit_NotSharedWithLogin(t *testing.T) {
	rl := newAuthRL(t, middleware.DefaultAuthRateLimitConfig())
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	login := rl.LoginMiddleware()(ok)
	mfa := rl.MFAMiddleware()(ok)

	// Exhaust the login bucket from this IP.
	for i := 0; i < 10; i++ {
		login.ServeHTTP(httptest.NewRecorder(), loginPost())
	}
	rec := httptest.NewRecorder()
	login.ServeHTTP(rec, loginPost())
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("login bucket should be exhausted, got %d", rec.Code)
	}

	// A mistyped code and the correct one still go through.
	for i := 0; i < 2; i++ {
		rec = httptest.NewRecorder()
		mfa.ServeHTTP(rec, mfaPost("challenge-a"))
		if rec.Code != http.StatusOK {
			t.Fatalf("mfa attempt %d after login burst: got %d, want 200", i+1, rec.Code)
		}
	}
}

func TestMFARateLimit_PerChallengeBucket(t *testing.T) {
	cfg := middleware.DefaultAuthRateLimitConfig()
	cfg.MFARatePerMin = 3
	cfg.MFAIPRatePerMin = 100
	rl := newAuthRL(t, cfg)
	var seen string
	h := rl.MFAMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The body is still readable by the handler.
		b, _ := io.ReadAll(r.Body)
		var v map[string]string
		_ = json.Unmarshal(b, &v)
		seen = v["mfa_token"]
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, mfaPost("challenge-a"))
		if rec.Code != http.StatusOK || seen != "challenge-a" {
			t.Fatalf("attempt %d: got %d (handler saw %q)", i+1, rec.Code, seen)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, mfaPost("challenge-a"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("4th attempt on one challenge: got %d, want 429", rec.Code)
	}
	var e struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &e)
	if e.Code != "RATE_LIMIT_EXCEEDED" {
		t.Errorf("429 code: got %q, want RATE_LIMIT_EXCEEDED", e.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 must carry Retry-After")
	}

	// Another challenge (another sign-in) has its own bucket.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, mfaPost("challenge-b"))
	if rec.Code != http.StatusOK {
		t.Fatalf("other challenge: got %d, want 200", rec.Code)
	}
}

func TestMFARateLimit_PerIPCeiling(t *testing.T) {
	cfg := middleware.DefaultAuthRateLimitConfig()
	cfg.MFARatePerMin = 100
	cfg.MFAIPRatePerMin = 4
	rl := newAuthRL(t, cfg)
	h := rl.MFAMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	// Spraying many challenges from one IP hits the IP ceiling.
	for i := 0; i < 4; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, mfaPost("c"+strings.Repeat("x", i)))
		if rec.Code != http.StatusOK {
			t.Fatalf("attempt %d: got %d", i+1, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, mfaPost("c-new"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over the per-IP MFA ceiling: got %d, want 429", rec.Code)
	}
}
