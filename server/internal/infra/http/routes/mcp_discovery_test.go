package routes

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	apikeydom "github.com/openctemio/openctem/api/pkg/domain/apikey"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type refuseEveryKey struct{}

func (refuseEveryKey) AuthenticateWithPermissions(context.Context, string, string) (*apikeydom.APIKey, []string, error) {
	return nil, nil, errors.New("unknown key")
}

func newMCPDiscoveryMux(t *testing.T) http.Handler {
	t.Helper()
	e, err := mcpoauth.NewEndpoints("https://openctem.example")
	if err != nil {
		t.Fatal(err)
	}
	log := logger.NewNop()
	router := infrahttp.NewChiRouter()
	d := &MCPDiscovery{Endpoints: e, Metadata: handler.NewMCPResourceMetadataHandler(e), AllowedOrigins: []string{"http://localhost:3000"}}
	mcp := handler.NewMCPHandler(nil, nil, nil, nil, nil, nil, nil, log)
	registerMCPRoutes(router, mcp, nil, middleware.NewAPIKeyAuth(refuseEveryKey{}, log).Handler, d)
	return router.(interface{ Handler() http.Handler }).Handler()
}

// An MCP client that knows only the endpoint URL can discover the
// authorization server: the refusal names the metadata, and the metadata is
// served at both RFC 9728 locations.
func TestMCPDiscoveryRoutes(t *testing.T) {
	mux := newMCPDiscoveryMux(t)

	for _, path := range []string{
		"/.well-known/oauth-protected-resource/api/v1/mcp",
		"/.well-known/oauth-protected-resource",
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"resource":"https://openctem.example/api/v1/mcp"`) {
			t.Fatalf("GET %s: %d %s", path, rec.Code, rec.Body.String())
		}
	}

	for name, auth := range map[string]string{
		"no credential":    "",
		"unknown oct_ key": "Bearer oct_nope",
		"other bearer":     "Bearer eyJhbGciOiJIUzI1NiJ9.e30.x",
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		ch := rec.Header().Get("WWW-Authenticate")
		if rec.Code != http.StatusUnauthorized || !strings.Contains(ch, `resource_metadata="https://openctem.example/.well-known/oauth-protected-resource/api/v1/mcp"`) {
			t.Errorf("%s: status %d, WWW-Authenticate %q", name, rec.Code, ch)
		}
	}
}

// A browser page on a foreign origin is refused before authentication; the
// public origin and the configured CORS origins pass to authentication.
func TestMCPEndpointOriginGuard(t *testing.T) {
	mux := newMCPDiscoveryMux(t)
	for origin, want := range map[string]int{
		"https://evil.example":     http.StatusForbidden,
		"https://openctem.example": http.StatusUnauthorized,
		"http://localhost:3000":    http.StatusUnauthorized,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", strings.NewReader(`{}`))
		req.Header.Set("Origin", origin)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Origin %s: status %d, want %d", origin, rec.Code, want)
		}
	}
}

// Without a public URL the endpoint keeps working with keys and serves no
// metadata.
func TestMCPWithoutDiscovery(t *testing.T) {
	log := logger.NewNop()
	router := infrahttp.NewChiRouter()
	registerMCPRoutes(router, handler.NewMCPHandler(nil, nil, nil, nil, nil, nil, nil, log), nil,
		middleware.NewAPIKeyAuth(refuseEveryKey{}, log).Handler, nil)
	mux := router.(interface{ Handler() http.Handler }).Handler()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil))
	if rec.Code == http.StatusOK {
		t.Fatal("metadata served without a public URL")
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/mcp", strings.NewReader(`{}`)))
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("status %d, challenge %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}
