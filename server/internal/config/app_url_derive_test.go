package config

import (
	"slices"
	"strings"
	"testing"
)

func devEnv(t *testing.T) {
	t.Helper()
	t.Setenv("APP_ENV", "development")
	t.Setenv("AUTH_PROVIDER", "")
	t.Setenv("AUTH_JWT_SECRET", strings.Repeat("a", 64))
	for _, k := range []string{"CORS_ALLOWED_ORIGINS", "SMTP_BASE_URL", "OAUTH_FRONTEND_CALLBACK_URL", "SSO_ALLOWED_REDIRECT_URIS"} {
		t.Setenv(k, "")
	}
}

// APP_URL alone sets the CORS allow-list, the email link base and the OAuth
// callback: one public URL instead of four variables that must agree.
func TestLoad_AppURLDerivesFrontendURLs(t *testing.T) {
	devEnv(t)
	t.Setenv("APP_URL", "https://ctem.example.com/")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !slices.Equal(cfg.CORS.AllowedOrigins, []string{"https://ctem.example.com"}) {
		t.Errorf("CORS origins = %v, want only the APP_URL origin", cfg.CORS.AllowedOrigins)
	}
	if cfg.SMTP.BaseURL != "https://ctem.example.com" {
		t.Errorf("SMTP base = %q", cfg.SMTP.BaseURL)
	}
	if cfg.OAuth.FrontendCallbackURL != "https://ctem.example.com/auth/callback" {
		t.Errorf("OAuth callback = %q", cfg.OAuth.FrontendCallbackURL)
	}
	if !slices.Equal(cfg.Auth.AllowedRedirectURIs, []string{"https://ctem.example.com"}) {
		t.Errorf("SSO redirect allow-list = %v, want only the APP_URL origin", cfg.Auth.AllowedRedirectURIs)
	}
}

// An explicit value still wins over the derived one.
func TestLoad_ExplicitFrontendURLsWin(t *testing.T) {
	devEnv(t)
	t.Setenv("APP_URL", "https://api.example.com")
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://console.example.com")
	t.Setenv("SMTP_BASE_URL", "https://console.example.com")
	t.Setenv("OAUTH_FRONTEND_CALLBACK_URL", "https://console.example.com/auth/callback")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !slices.Equal(cfg.CORS.AllowedOrigins, []string{"https://console.example.com"}) ||
		cfg.SMTP.BaseURL != "https://console.example.com" ||
		cfg.OAuth.FrontendCallbackURL != "https://console.example.com/auth/callback" {
		t.Errorf("explicit values lost: %v %q %q", cfg.CORS.AllowedOrigins, cfg.SMTP.BaseURL, cfg.OAuth.FrontendCallbackURL)
	}
}

// Without APP_URL the development defaults stay.
func TestLoad_NoAppURLKeepsLocalhostDefaults(t *testing.T) {
	devEnv(t)
	t.Setenv("APP_URL", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !slices.Equal(cfg.CORS.AllowedOrigins, []string{"http://localhost:3000"}) || cfg.SMTP.BaseURL != "http://localhost:3000" {
		t.Errorf("defaults changed: %v %q", cfg.CORS.AllowedOrigins, cfg.SMTP.BaseURL)
	}
}

// A malformed APP_URL would otherwise widen nothing but silently fall back to
// localhost links in every email; refuse it instead. Credentials in the URL
// would leak into every derived link.
func TestLoad_RefusesInvalidAppURL(t *testing.T) {
	for _, bad := range []string{"ctem.example.com", "ftp://ctem.example.com", "https://user:pw@ctem.example.com", "https://ctem.example.com/?x=1", "https://ctem.example.com/#f", "javascript:alert(1)"} {
		devEnv(t)
		t.Setenv("APP_URL", bad)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "APP_URL") {
			t.Errorf("APP_URL=%q: err = %v, want a refusal naming APP_URL", bad, err)
		}
	}
}
