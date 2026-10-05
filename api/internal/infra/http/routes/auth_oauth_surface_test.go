package routes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/config"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// oauthTestConfig returns a config with all three social providers fully
// credentialed, i.e. an operator who has explicitly asked for social login.
func oauthTestConfig() *config.Config {
	provider := func(id string) config.OAuthProviderConfig {
		return config.OAuthProviderConfig{
			Enabled:      true,
			ClientID:     id + "-client-id",
			ClientSecret: id + "-client-secret",
		}
	}
	return &config.Config{
		Auth: config.AuthConfig{
			JWTSecret: "test-jwt-secret-value-0123456789abcdef",
			JWTIssuer: "openctem-test",
		},
		OAuth: config.OAuthConfig{
			Enabled:             true,
			FrontendCallbackURL: "http://localhost:3000/auth/callback",
			StateSecret:         "test-state-secret-value-0123456789",
			Google:              provider("google"),
			GitHub:              provider("github"),
			Microsoft:           provider("microsoft"),
		},
	}
}

// advertisedProviders registers the auth routes for the given Handlers and
// returns the social-provider snapshot the UI reads from /auth/providers,
// together with the router so route existence can be probed.
func advertisedProviders(t *testing.T, h Handlers) (handler.SocialProviders, http.Handler) {
	t.Helper()

	router := infrahttp.NewChiRouter()
	registerAuthRoutes(router, h, oauthTestConfig(), AuthConfig{}, nil, nil, logger.NewNop())

	srv, ok := router.(interface{ Handler() http.Handler })
	if !ok {
		t.Fatalf("router does not expose Handler()")
	}
	mux := srv.Handler()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/providers", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/auth/providers = %d, want 200", rec.Code)
	}

	var resp handler.AuthProvidersResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode /auth/providers: %v", err)
	}
	return resp.Social, mux
}

// routeExists reports whether the router has a route registered for path.
// A registered route may still reject the request (400/403), but an
// unregistered one yields 404 — which is exactly the dead button the UI hits.
func routeExists(mux http.Handler, path string) bool {
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code != http.StatusNotFound
}

// TestAuthProviders_NeverAdvertisesUnroutedProvider is the regression guard for
// the "Sign in with Google/GitHub 404s" bug.
//
// /auth/providers is what the login page uses to decide which social buttons to
// render. It used to report purely from OAUTH_* config, while the
// /auth/oauth/{provider}/authorize routes were registered only when the OAuth
// handler was wired into the composition root — which it never was. So an
// operator who set OAUTH_GOOGLE_CLIENT_ID/SECRET got a Google button whose
// click 404'd.
//
// This asserts the invariant directly: a provider is advertised only if its
// routes exist.
func TestAuthProviders_NeverAdvertisesUnroutedProvider(t *testing.T) {
	// Handlers with no OAuth handler — the composition root as it shipped.
	social, mux := advertisedProviders(t, Handlers{})

	for _, p := range []struct {
		name       string
		advertised bool
	}{
		{"google", social.Google},
		{"github", social.GitHub},
		{"microsoft", social.Microsoft},
	} {
		t.Run(p.name, func(t *testing.T) {
			authorizePath := "/api/v1/auth/oauth/" + p.name + "/authorize"
			live := routeExists(mux, authorizePath)

			if live {
				t.Fatalf("expected %s to be unregistered when Handlers.OAuth is nil", authorizePath)
			}
			if p.advertised {
				t.Errorf("/auth/providers advertises %q but %s is not registered — "+
					"the login page will render a button that 404s", p.name, authorizePath)
			}
		})
	}
}

// TestAuthProviders_AdvertisesWiredProviders is the other half of the
// invariant: once the OAuth handler IS wired, the configured providers are
// advertised again and their routes really are reachable. Without this, a fix
// that simply hardcoded every provider to false would also pass.
func TestAuthProviders_AdvertisesWiredProviders(t *testing.T) {
	cfg := oauthTestConfig()
	// Repos are nil: the authorize leg builds the provider URL from config and
	// a signed state token, and never touches persistence.
	oauthSvc := auth.NewOAuthService(nil, nil, nil, cfg.OAuth, cfg.Auth, logger.NewNop())
	oauthHandler := handler.NewOAuthHandler(oauthSvc, cfg.OAuth, cfg.Auth, logger.NewNop())

	social, mux := advertisedProviders(t, Handlers{OAuth: oauthHandler})

	for _, p := range []struct {
		name       string
		advertised bool
		wantHost   string
	}{
		{"google", social.Google, "accounts.google.com"},
		{"github", social.GitHub, "github.com"},
		{"microsoft", social.Microsoft, "login.microsoftonline.com"},
	} {
		t.Run(p.name, func(t *testing.T) {
			if !p.advertised {
				t.Errorf("/auth/providers should advertise %q when it is configured and wired", p.name)
			}

			authorizePath := "/api/v1/auth/oauth/" + p.name + "/authorize"
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, authorizePath, nil))

			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s = %d (body %s), want 200", authorizePath, rec.Code, rec.Body.String())
			}

			// The button must lead somewhere real: a provider authorization URL
			// carrying the state token the UI stores for the callback leg.
			var resp handler.AuthorizeResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode authorize response: %v", err)
			}
			if resp.State == "" {
				t.Error("authorize response has no state token")
			}
			u, err := url.Parse(resp.AuthorizationURL)
			if err != nil {
				t.Fatalf("authorization_url is not a URL: %v", err)
			}
			if u.Host != p.wantHost {
				t.Errorf("authorization_url host = %q, want %q", u.Host, p.wantHost)
			}
			if got := u.Query().Get("client_id"); got != p.name+"-client-id" {
				t.Errorf("authorization_url client_id = %q, want %q", got, p.name+"-client-id")
			}
		})
	}
}

// /auth/providers is a config read the UI makes on many screens. It must not
// share the login limiter (5 per minute per IP): it used to, so reading it
// spent the caller's login budget and a user who opened a few pages got 429
// on the login itself. Ten reads in a row all succeed, and are cacheable.
func TestAuthProviders_NotOnTheLoginLimiter(t *testing.T) {
	cfg := oauthTestConfig()
	cfg.RateLimit = config.RateLimitConfig{Enabled: true, RequestsPerSec: 100, Burst: 200, CleanupInterval: time.Minute}
	router := infrahttp.NewChiRouter()
	registerAuthRoutes(router, Handlers{}, cfg, AuthConfig{}, nil, nil, logger.NewNop())
	mux := router.(interface{ Handler() http.Handler }).Handler()

	for i := 1; i <= 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/providers", nil)
		req.RemoteAddr = "203.0.113.7:4000"
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("read %d: status %d, want 200 (still on the login limiter?)", i, rec.Code)
		}
		if i == 1 && rec.Header().Get("Cache-Control") != "public, max-age=60" {
			t.Errorf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
		}
	}
}
