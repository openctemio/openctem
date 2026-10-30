package routes

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
)

// gate lets a request through only when it carries the given header, standing
// in for the user session (authMiddleware) or the console session.
func gate(header string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get(header) == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func docsMux(t *testing.T, production bool) http.Handler {
	t.Helper()
	spec := filepath.Join(t.TempDir(), "swagger.yaml")
	if err := os.WriteFile(spec, []byte("swagger: \"2.0\"\nhost: localhost:8080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	router := infrahttp.NewChiRouter()
	registerDocsRoutes(router, handler.NewDocsHandler(spec), production, gate("X-User"), gate("X-Console"), nil)
	return router.(interface{ Handler() http.Handler }).Handler()
}

func docsGet(mux http.Handler, path string, headers ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, h := range headers {
		req.Header.Set(h, "1")
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// In production the API reference page is not public and the spec needs a
// signed-in user; platform administrators read both through the console.
func TestDocsRoutes_Production(t *testing.T) {
	mux := docsMux(t, true)

	if rec := docsGet(mux, "/docs"); rec.Code != http.StatusNotFound {
		t.Errorf("GET /docs in production: got %d, want 404", rec.Code)
	}
	if rec := docsGet(mux, "/openapi.yaml"); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous GET /openapi.yaml in production: got %d, want 401", rec.Code)
	}
	if rec := docsGet(mux, "/openapi.yaml", "X-User"); rec.Code != http.StatusOK {
		t.Errorf("signed-in GET /openapi.yaml in production: got %d, want 200", rec.Code)
	}
	// A tenant user session is not a console session.
	for _, p := range []string{"/api/v1/admin/docs", "/api/v1/admin/openapi.yaml"} {
		if rec := docsGet(mux, p, "X-User"); rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s with a user session: got %d, want 401", p, rec.Code)
		}
		if rec := docsGet(mux, p, "X-Console"); rec.Code != http.StatusOK {
			t.Errorf("GET %s with a console session: got %d, want 200", p, rec.Code)
		}
	}
	page := docsGet(mux, "/api/v1/admin/docs", "X-Console").Body.String()
	if !strings.Contains(page, `"/api/v1/admin/openapi.yaml"`) {
		t.Errorf("console page must load the console spec route")
	}
}

// Outside production the page and the spec stay public for development.
func TestDocsRoutes_Development(t *testing.T) {
	mux := docsMux(t, false)
	for _, p := range []string{"/docs", "/openapi.yaml"} {
		if rec := docsGet(mux, p); rec.Code != http.StatusOK {
			t.Errorf("anonymous GET %s outside production: got %d, want 200", p, rec.Code)
		}
	}
}

// The page runs only the pinned, integrity-checked script and never builds a
// URL from the Host header.
func TestDocsPage_PinnedScriptNoHostHeader(t *testing.T) {
	mux := docsMux(t, false)
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	req.Host = "evil.example"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	page := rec.Body.String()
	if strings.Contains(page, "evil.example") || strings.Contains(rec.Header().Get("Content-Security-Policy"), "evil.example") {
		t.Errorf("the page or its CSP echoes the Host header")
	}
	if !strings.Contains(page, `integrity="sha256-`) || !strings.Contains(page, "@scalar/api-reference@") {
		t.Errorf("the script must be version-pinned with an integrity hash")
	}
}
