package middleware

// End-to-end CSRF tests.
//
// These exercise the CSRF middleware exactly as a real HTTP request
// would see it: full cookie jar, real http.Request, real response
// writer. The goal is not to re-test pure string compare (covered by
// crypto/subtle) but to pin the HTTP-layer contract that the backend
// owes to browser clients + the Next.js proxy:
//
//   1. Safe methods (GET/HEAD/OPTIONS) are always exempt.
//   2. For state-changing methods:
//      - strict `CSRF` requires BOTH cookie and header to be set
//        and match (double-submit-cookie).
//      - `CSRFOptional` lets through cookie-less clients (API key /
//        bearer / integration tests) but enforces for anyone who
//        carries the cookie.
//   3. Every rejection bumps the right metrics label.
//   4. Token-cookie round-trip (GenerateCSRFToken →
//      SetCSRFTokenCookie → client re-reads → header) works.
//
// Running: `cd api && GOWORK=off go test ./internal/infra/http/middleware -run CSRF`.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/api/internal/metrics"
	"github.com/openctemio/api/pkg/logger"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// --- helpers --------------------------------------------------------

// okHandler is the "protected resource" sitting behind the middleware.
// If control reaches it, the middleware let the request through.
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func testCSRFConfig() CSRFConfig {
	return CSRFConfig{
		Path:     "/",
		TTL:      1 * time.Hour,
		SameSite: http.SameSiteLaxMode,
		Logger:   logger.New(logger.Config{Level: "error"}),
	}
}

// newRequestWithCookie constructs a request with the csrf_token
// cookie + an optional X-CSRF-Token header. Pass empty strings to
// omit either.
func newRequestWithCookie(t *testing.T, method, path, cookieVal, headerVal string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if cookieVal != "" {
		req.AddCookie(&http.Cookie{Name: CSRFTokenCookieName, Value: cookieVal})
	}
	if headerVal != "" {
		req.Header.Set(CSRFHeaderName, headerVal)
	}
	return req
}

// execCSRF runs the request through the CSRF middleware and returns
// the recorder. Callers check status + body + metric deltas.
func execCSRF(middleware func(http.Handler) http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	middleware(okHandler()).ServeHTTP(rr, req)
	return rr
}

// readMetric returns the current value of CSRFRejectionsTotal for the
// given (reason, method) label pair. Uses testutil.ToFloat64 which
// handles the Vec → Counter unwrap correctly.
func readMetric(reason, method string) float64 {
	return testutil.ToFloat64(metrics.CSRFRejectionsTotal.WithLabelValues(reason, method))
}

// -----------------------------------------------------------------
// Safe methods are exempt from CSRF validation (both strict + optional)
// -----------------------------------------------------------------

func TestCSRF_SafeMethods_AlwaysPass(t *testing.T) {
	mw := CSRF(testCSRFConfig())
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/v1/whatever", nil)
			rr := execCSRF(mw, req)
			if rr.Code != http.StatusOK {
				t.Errorf("%s with no cookie/header must pass (safe method); got %d", method, rr.Code)
			}
		})
	}
}

func TestCSRFOptional_SafeMethods_AlwaysPass(t *testing.T) {
	mw := CSRFOptional(testCSRFConfig())
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/v1/whatever", nil)
			rr := execCSRF(mw, req)
			if rr.Code != http.StatusOK {
				t.Errorf("%s with no cookie/header must pass (safe method); got %d", method, rr.Code)
			}
		})
	}
}

// -----------------------------------------------------------------
// CSRF strict
// -----------------------------------------------------------------

// Browser cookie-bound client that correctly sends both → pass.
func TestCSRF_Strict_CookieAndMatchingHeader_Pass(t *testing.T) {
	tok := randomTokenForTest(t)
	req := newRequestWithCookie(t, http.MethodPost, "/api/v1/findings", tok, tok)
	rr := execCSRF(CSRF(testCSRFConfig()), req)
	if rr.Code != http.StatusOK {
		t.Fatalf("matching cookie+header must pass; got %d body=%s", rr.Code, rr.Body.String())
	}
}

// No cookie at all on a mutation → strict mode refuses. This is the
// branch that protects us from cookie-less CSRF attempts AND is the
// reason we ship CSRFOptional today (bearer-token clients would hit
// this otherwise).
func TestCSRF_Strict_NoCookie_Rejects(t *testing.T) {
	before := readMetric("missing_cookie", http.MethodPost)
	req := newRequestWithCookie(t, http.MethodPost, "/api/v1/findings", "", "")
	rr := execCSRF(CSRF(testCSRFConfig()), req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("missing cookie must be 403; got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "CSRF") {
		t.Errorf("reject body should mention CSRF; got %s", rr.Body.String())
	}
	// Metric incremented with the right label pair.
	after := readMetric("missing_cookie", http.MethodPost)
	if after != before+1 {
		t.Errorf("CSRFRejectionsTotal{reason=missing_cookie,method=POST}: want +1, got before=%v after=%v", before, after)
	}
}

// Cookie set but header missing → reject for missing_header.
func TestCSRF_Strict_CookieButNoHeader_Rejects(t *testing.T) {
	tok := randomTokenForTest(t)
	before := readMetric("missing_header", http.MethodPost)
	req := newRequestWithCookie(t, http.MethodPost, "/api/v1/findings", tok, "")
	rr := execCSRF(CSRF(testCSRFConfig()), req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("missing header with cookie present must be 403; got %d", rr.Code)
	}
	after := readMetric("missing_header", http.MethodPost)
	if after != before+1 {
		t.Errorf("missing_header counter not incremented; before=%v after=%v", before, after)
	}
}

// Cookie + header both present but mismatched → token_mismatch.
// This is the actual CSRF defence firing: attacker's cross-site form
// has no way to read the victim's cookie, so their forged header
// cannot match.
func TestCSRF_Strict_CookieHeaderMismatch_Rejects(t *testing.T) {
	cookieTok := randomTokenForTest(t)
	headerTok := randomTokenForTest(t)
	if cookieTok == headerTok {
		t.Fatal("test precondition: two randomly-generated tokens collided — re-run")
	}
	before := readMetric("token_mismatch", http.MethodPost)

	req := newRequestWithCookie(t, http.MethodPost, "/api/v1/findings", cookieTok, headerTok)
	rr := execCSRF(CSRF(testCSRFConfig()), req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("mismatched tokens must be 403; got %d", rr.Code)
	}
	after := readMetric("token_mismatch", http.MethodPost)
	if after != before+1 {
		t.Errorf("token_mismatch counter not incremented; before=%v after=%v", before, after)
	}
}

// A prefix collision in cookie/header must NOT pass. Catches a class
// of bugs where someone swapped the constant-time compare for a
// naive `strings.HasPrefix` optimization.
func TestCSRF_Strict_PrefixCollision_Rejects(t *testing.T) {
	cookieTok := randomTokenForTest(t)
	headerTok := cookieTok[:len(cookieTok)-4] + "XXXX"

	req := newRequestWithCookie(t, http.MethodPost, "/api/v1/findings", cookieTok, headerTok)
	rr := execCSRF(CSRF(testCSRFConfig()), req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("prefix-matching-but-not-equal tokens must be 403; got %d", rr.Code)
	}
}

// Empty-string header with empty-string cookie is rejected the same
// way as "no cookie" (both triggers the missing_cookie branch).
// This pins the semantics: the middleware treats an empty cookie
// value as absent, matching Set-Cookie MaxAge=-1 semantics.
func TestCSRF_Strict_EmptyCookieValue_Rejects(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings", nil)
	req.AddCookie(&http.Cookie{Name: CSRFTokenCookieName, Value: ""})
	rr := execCSRF(CSRF(testCSRFConfig()), req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("empty cookie value must be treated as missing; got %d", rr.Code)
	}
}

// -----------------------------------------------------------------
// CSRF optional — the production posture today.
// Pins the three meaningful branches:
//
//   1. No cookie → pass (API key / bearer / future mobile clients)
//   2. Cookie present, header missing → 403
//   3. Cookie present, header matches → pass
//
// This is the "safe rollout" path documented in routes.go — once
// real users bring their CSRF header consistently we flip to strict.
// -----------------------------------------------------------------

func TestCSRFOptional_NoCookie_PassesThrough(t *testing.T) {
	// Critical: this is the branch that MUST NOT break API-key and
	// bearer-token clients. If this test fails, we've lost the
	// promise of safe rollout — flipping the lever would then break
	// every bearer-authenticated flow on first deploy.
	req := newRequestWithCookie(t, http.MethodPost, "/api/v1/findings", "", "")
	rr := execCSRF(CSRFOptional(testCSRFConfig()), req)
	if rr.Code != http.StatusOK {
		t.Fatalf("CSRFOptional with no cookie must pass (bearer/API-key clients); got %d", rr.Code)
	}
}

func TestCSRFOptional_CookiePresentNoHeader_Rejects(t *testing.T) {
	tok := randomTokenForTest(t)
	before := readMetric("missing_header", http.MethodPost)

	req := newRequestWithCookie(t, http.MethodPost, "/api/v1/findings", tok, "")
	rr := execCSRF(CSRFOptional(testCSRFConfig()), req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("CSRFOptional with cookie but no header must be 403; got %d", rr.Code)
	}
	after := readMetric("missing_header", http.MethodPost)
	if after != before+1 {
		t.Errorf("missing_header counter: want +1, got before=%v after=%v", before, after)
	}
}

func TestCSRFOptional_CookieMatchingHeader_Passes(t *testing.T) {
	tok := randomTokenForTest(t)
	req := newRequestWithCookie(t, http.MethodPost, "/api/v1/findings", tok, tok)
	rr := execCSRF(CSRFOptional(testCSRFConfig()), req)
	if rr.Code != http.StatusOK {
		t.Fatalf("CSRFOptional with matching cookie+header must pass; got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCSRFOptional_CookieMismatch_Rejects(t *testing.T) {
	before := readMetric("token_mismatch", http.MethodPost)
	cookieTok := randomTokenForTest(t)
	headerTok := randomTokenForTest(t)

	req := newRequestWithCookie(t, http.MethodPost, "/api/v1/findings", cookieTok, headerTok)
	rr := execCSRF(CSRFOptional(testCSRFConfig()), req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("CSRFOptional with mismatched cookie+header must be 403; got %d", rr.Code)
	}
	after := readMetric("token_mismatch", http.MethodPost)
	if after != before+1 {
		t.Errorf("token_mismatch counter: want +1, got before=%v after=%v", before, after)
	}
}

// All the state-changing methods must be gated identically — PUT,
// PATCH, DELETE sometimes slip through if the middleware special-
// cases POST only. Matrix test pins the HTTP-method list.
func TestCSRFOptional_AllStateChangingMethods_Gated(t *testing.T) {
	tok := randomTokenForTest(t)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			req := newRequestWithCookie(t, method, "/api/v1/findings", tok, "") // no header
			rr := execCSRF(CSRFOptional(testCSRFConfig()), req)
			if rr.Code != http.StatusForbidden {
				t.Errorf("%s with cookie but no header must be 403; got %d", method, rr.Code)
			}
		})
	}
}

// -----------------------------------------------------------------
// Token round-trip: the token the middleware hands out via
// SetCSRFTokenCookie must be accepted back when the client echoes
// it into the X-CSRF-Token header. Lines up the generator, the
// cookie setter, and the validator.
// -----------------------------------------------------------------

func TestCSRF_RoundTrip_GeneratedTokenIsAcceptedBack(t *testing.T) {
	// Step 1: server generates + sets cookie (what the login handler
	// does).
	tok := randomTokenForTest(t)
	w := httptest.NewRecorder()
	SetCSRFTokenCookie(w, tok, testCSRFConfig())

	// Pull the cookie back out of the response — simulates the
	// browser reading Set-Cookie. We read via Header().Get so this
	// also exercises the Set-Cookie serialization path.
	rawCookie := w.Header().Get("Set-Cookie")
	if rawCookie == "" {
		t.Fatal("SetCSRFTokenCookie emitted no Set-Cookie header")
	}
	if !strings.Contains(rawCookie, CSRFTokenCookieName+"="+tok) {
		t.Fatalf("Set-Cookie missing token; got %q", rawCookie)
	}

	// Step 2: client re-submits the same token in the header on a
	// mutation request.
	req := newRequestWithCookie(t, http.MethodPost, "/api/v1/findings", tok, tok)
	rr := execCSRF(CSRF(testCSRFConfig()), req)
	if rr.Code != http.StatusOK {
		body, _ := io.ReadAll(rr.Body)
		t.Fatalf("round-trip token rejected; got %d body=%s", rr.Code, string(body))
	}
}

// Cookie is JS-readable (HttpOnly=false) on purpose — that's what
// lets the client JS read and re-send it. A future refactor that
// flips HttpOnly=true silently would break the entire CSRF flow.
func TestSetCSRFTokenCookie_NotHttpOnly(t *testing.T) {
	w := httptest.NewRecorder()
	SetCSRFTokenCookie(w, "abc123", testCSRFConfig())
	raw := w.Header().Get("Set-Cookie")
	if strings.Contains(strings.ToLower(raw), "httponly") {
		t.Errorf("csrf_token cookie MUST NOT be HttpOnly (client JS needs to read it); got %q", raw)
	}
}

// -----------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------

// randomTokenForTest returns a fresh URL-safe CSRF token via the
// real GenerateCSRFToken path. Having tests use the real generator
// means any regression in token entropy / encoding shows up in this
// suite.
func randomTokenForTest(t *testing.T) string {
	t.Helper()
	tok, err := GenerateCSRFToken()
	if err != nil {
		t.Fatalf("GenerateCSRFToken: %v", err)
	}
	return tok
}
