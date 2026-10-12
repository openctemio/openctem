package routes

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/config"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// authMux registers the auth routes for provider with both the local and the
// OIDC handler wired, as the composition root does in hybrid mode.
func authMux(t *testing.T, provider config.AuthProvider) http.Handler {
	t.Helper()
	cfg := oauthTestConfig()
	cfg.Auth.Provider = provider
	h := Handlers{
		LocalAuth: handler.NewLocalAuthHandler(nil, nil, nil, nil, cfg.Auth, logger.NewNop()),
		Auth:      handler.NewAuthHandler(&config.KeycloakConfig{BaseURL: "https://idp.example.test", Realm: "r"}, logger.NewNop()),
	}
	router := infrahttp.NewChiRouter()
	passThrough := func(next http.Handler) http.Handler { return next }
	registerAuthRoutes(router, h, cfg, AuthConfig{Provider: provider}, passThrough, nil, logger.NewNop())
	return router.(interface{ Handler() http.Handler }).Handler()
}

func postToken(mux http.Handler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// In hybrid mode POST /auth/token is the local tenant token exchange. It used
// to be registered a second time for OIDC, and the later registration (a
// deprecated stub that answered 200 with an IdP URL and no token) shadowed
// the exchange, so switching tenants broke for local users.
func TestAuthTokenRoute_HybridServesLocalExchange(t *testing.T) {
	for _, provider := range []config.AuthProvider{config.AuthProviderLocal, config.AuthProviderHybrid} {
		t.Run(string(provider), func(t *testing.T) {
			mux := authMux(t, provider)

			// Requests that the local exchange rejects before any service call:
			// the stub would have answered 200 to both.
			rec := postToken(mux, `{}`)
			if rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), "auth_url") {
				t.Fatalf("POST /auth/token {} = %d %s: not the local exchange", rec.Code, rec.Body.String())
			}
			if rec.Code != http.StatusBadRequest && rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("POST /auth/token {} = %d, want a validation error", rec.Code)
			}
			rec = postToken(mux, `{"tenant_id":"t-1"}`)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "refresh_token is required") {
				t.Fatalf("POST /auth/token without a refresh token = %d %s, want the local 400", rec.Code, rec.Body.String())
			}
		})
	}
}

// With OIDC only, the identity provider issues tokens: the platform has no
// token endpoint (fail closed rather than a 200 that issues nothing), and the
// OIDC routes that remain are still served.
func TestAuthTokenRoute_OIDCOnlyHasNoTokenEndpoint(t *testing.T) {
	mux := authMux(t, config.AuthProviderOIDC)
	if rec := postToken(mux, `{"tenant_id":"t-1","refresh_token":"x"}`); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /auth/token in OIDC mode = %d %s, want no route", rec.Code, rec.Body.String())
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/info", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "idp.example.test") {
		t.Fatalf("GET /auth/info in OIDC mode = %d %s, want the IdP info", rec.Code, rec.Body.String())
	}
}
