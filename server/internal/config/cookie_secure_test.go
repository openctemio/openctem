package config

import (
	"strings"
	"testing"
)

func TestDefaultCookieSecure(t *testing.T) {
	cases := map[string]bool{
		"development": false, // plain http://localhost
		"production":  true,
		"staging":     true,
		"":            true, // unknown env is treated as non-dev
	}
	for env, want := range cases {
		if got := defaultCookieSecure(env); got != want {
			t.Errorf("defaultCookieSecure(%q) = %v, want %v", env, got, want)
		}
	}
}

// Production must refuse insecure cookies for every auth provider, not only
// local/hybrid: SSO callbacks, the admin console and the CSRF cookie are set
// whatever the provider.
func TestValidateProductionAuth_RequiresSecureCookiesForEveryProvider(t *testing.T) {
	for _, p := range []AuthProvider{AuthProviderLocal, AuthProviderHybrid, AuthProviderOIDC} {
		cfg := minimalValidConfig()
		cfg.App.Env = EnvProduction
		cfg.Auth.Provider = p
		cfg.Auth.CookieSecure = false
		err := cfg.validateProductionAuth()
		if err == nil || !strings.Contains(err.Error(), "AUTH_COOKIE_SECURE") {
			t.Errorf("provider %q: want AUTH_COOKIE_SECURE error, got %v", p, err)
		}
		cfg.Auth.CookieSecure = true
		cfg.Auth.CookieSameSite = "lax"
		cfg.Auth.JWTSecret = strings.Repeat("a", 64)
		if err := cfg.validateProductionAuth(); err != nil {
			t.Errorf("provider %q with secure cookies: unexpected error %v", p, err)
		}
	}
}
