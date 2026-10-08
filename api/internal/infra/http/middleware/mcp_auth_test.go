package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
)

func testEndpoints(t *testing.T) mcpoauth.Endpoints {
	t.Helper()
	e, err := mcpoauth.NewEndpoints("https://openctem.example")
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestMCPChallengeOnlyOn401(t *testing.T) {
	e := testEndpoints(t)
	want := `Bearer resource_metadata="https://openctem.example/.well-known/oauth-protected-resource/api/v1/mcp", scope="mcp:assets.read mcp:compliance.read mcp:findings.read mcp:pentest.read"`

	refuse := MCPChallenge(e)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		apierror.Unauthorized("Invalid credentials").WriteJSON(w)
	}))
	rec := httptest.NewRecorder()
	refuse.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/mcp", nil))
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != want {
		t.Fatalf("401: status %d, WWW-Authenticate %q; want %q", rec.Code, rec.Header().Get("WWW-Authenticate"), want)
	}

	for name, h := range map[string]http.HandlerFunc{
		"200 with body":    func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{}")) },
		"403":              func(w http.ResponseWriter, _ *http.Request) { apierror.Forbidden("no").WriteJSON(w) },
		"429":              func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTooManyRequests) },
		"202 notification": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) },
	} {
		rec := httptest.NewRecorder()
		MCPChallenge(e)(h).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/mcp", nil))
		if got := rec.Header().Get("WWW-Authenticate"); got != "" {
			t.Errorf("%s: WWW-Authenticate = %q, want none", name, got)
		}
	}

	// A handler that sets its own challenge (insufficient_scope) keeps it.
	own := `Bearer error="insufficient_scope"`
	rec = httptest.NewRecorder()
	MCPChallenge(e)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", own)
		w.WriteHeader(http.StatusUnauthorized)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/mcp", nil))
	if got := rec.Header().Get("WWW-Authenticate"); got != own {
		t.Fatalf("own challenge replaced: %q", got)
	}
}

func TestMCPOriginGuard(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	guard := MCPOriginGuard([]string{"https://openctem.example", "http://localhost:3000/", "*"})(ok)

	cases := map[string]int{
		"":                                      http.StatusOK, // non-browser client
		"https://openctem.example":              http.StatusOK,
		"HTTPS://OPENCTEM.EXAMPLE":              http.StatusOK,
		"http://localhost:3000":                 http.StatusOK,
		"https://evil.example":                  http.StatusForbidden,
		"http://openctem.example":               http.StatusForbidden, // scheme matters
		"null":                                  http.StatusForbidden, // sandboxed frame, file://
		"https://openctem.example.evil.example": http.StatusForbidden,
	}
	for origin, want := range cases {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		guard.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Origin %q: status %d, want %d", origin, rec.Code, want)
		}
	}
	// "*" in the allowed list never opens the guard.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", nil)
	req.Header.Set("Origin", "https://any.example")
	rec := httptest.NewRecorder()
	guard.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("wildcard allowed an origin: %d", rec.Code)
	}
}
