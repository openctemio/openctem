package unit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/internal/infra/http/handler"
)

func TestSetRefreshTokenCookie_Success(t *testing.T) {
	cfg := handler.CookieConfig{
		Secure:                 true,
		Domain:                 "example.com",
		SameSite:               http.SameSiteLaxMode,
		Path:                   "/api/v1/auth",
		RefreshTokenCookieName: "refresh_token",
	}

	rec := httptest.NewRecorder()
	token := "test-refresh-token"
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	handler.SetRefreshTokenCookie(rec, token, expiresAt, cfg)

	result := rec.Result()
	defer result.Body.Close()

	cookies := result.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != cfg.RefreshTokenCookieName {
		t.Errorf("expected cookie name %s, got %s", cfg.RefreshTokenCookieName, cookie.Name)
	}
	if cookie.Value != token {
		t.Errorf("expected cookie value %s, got %s", token, cookie.Value)
	}
	if !cookie.HttpOnly {
		t.Error("expected HttpOnly to be true")
	}
	if !cookie.Secure {
		t.Error("expected Secure to be true")
	}
	if cookie.Path != cfg.Path {
		t.Errorf("expected path %s, got %s", cfg.Path, cookie.Path)
	}
	if cookie.Domain != cfg.Domain {
		t.Errorf("expected domain %s, got %s", cfg.Domain, cookie.Domain)
	}
}

func TestClearRefreshTokenCookie_Success(t *testing.T) {
	cfg := handler.CookieConfig{
		Secure:                 true,
		Domain:                 "example.com",
		SameSite:               http.SameSiteLaxMode,
		Path:                   "/api/v1/auth",
		RefreshTokenCookieName: "refresh_token",
	}

	rec := httptest.NewRecorder()
	handler.ClearRefreshTokenCookie(rec, cfg)

	result := rec.Result()
	defer result.Body.Close()

	cookies := result.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != cfg.RefreshTokenCookieName {
		t.Errorf("expected cookie name %s, got %s", cfg.RefreshTokenCookieName, cookie.Name)
	}
	if cookie.Value != "" {
		t.Errorf("expected empty cookie value, got %s", cookie.Value)
	}
	if cookie.MaxAge != -1 {
		t.Errorf("expected MaxAge -1, got %d", cookie.MaxAge)
	}
}

func TestGetRefreshTokenFromCookie_Success(t *testing.T) {
	cfg := handler.CookieConfig{
		RefreshTokenCookieName: "refresh_token",
	}
	token := "test-refresh-token"
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token", nil)
	req.AddCookie(&http.Cookie{
		Name:  cfg.RefreshTokenCookieName,
		Value: token,
	})

	result := handler.GetRefreshTokenFromCookie(req, cfg)
	if result != token {
		t.Errorf("expected token %s, got %s", token, result)
	}
}

func TestGetRefreshTokenFromCookie_NoCookie(t *testing.T) {
	cfg := handler.CookieConfig{
		RefreshTokenCookieName: "refresh_token",
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token", nil)

	result := handler.GetRefreshTokenFromCookie(req, cfg)
	if result != "" {
		t.Errorf("expected empty string, got %s", result)
	}
}

func TestGetRefreshTokenFromCookie_CustomCookieName(t *testing.T) {
	cfg := handler.CookieConfig{
		RefreshTokenCookieName: "refresh_token",
	}
	token := "test-refresh-token"
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token", nil)
	req.AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: token,
	})

	result := handler.GetRefreshTokenFromCookie(req, cfg)
	if result != token {
		t.Errorf("expected token %s, got %s", token, result)
	}
}

func TestNewCookieConfig_StrictSameSite(t *testing.T) {
	authCfg := config.AuthConfig{
		CookieSecure:   true,
		CookieDomain:   "example.com",
		CookieSameSite: "strict",
	}

	cfg := handler.NewCookieConfig(authCfg)

	if cfg.SameSite != http.SameSiteStrictMode {
		t.Errorf("expected SameSiteStrictMode, got %v", cfg.SameSite)
	}
}

func TestNewCookieConfig_LaxSameSite(t *testing.T) {
	authCfg := config.AuthConfig{
		CookieSecure:   true,
		CookieDomain:   "example.com",
		CookieSameSite: "lax",
	}

	cfg := handler.NewCookieConfig(authCfg)

	if cfg.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSiteLaxMode, got %v", cfg.SameSite)
	}
}

func TestNewCookieConfig_NoneSameSite(t *testing.T) {
	authCfg := config.AuthConfig{
		CookieSecure:   true,
		CookieDomain:   "example.com",
		CookieSameSite: "none",
	}

	cfg := handler.NewCookieConfig(authCfg)

	if cfg.SameSite != http.SameSiteNoneMode {
		t.Errorf("expected SameSiteNoneMode, got %v", cfg.SameSite)
	}
}

func TestNewCookieConfig_CustomCookieName(t *testing.T) {
	authCfg := config.AuthConfig{
		CookieSecure:           true,
		CookieDomain:           "example.com",
		CookieSameSite:         "lax",
		RefreshTokenCookieName: "refresh_token",
	}

	cfg := handler.NewCookieConfig(authCfg)

	if cfg.RefreshTokenCookieName != "refresh_token" {
		t.Errorf("expected RefreshTokenCookieName 'refresh_token', got %s", cfg.RefreshTokenCookieName)
	}
}

func TestNewCookieConfig_DefaultCookieName(t *testing.T) {
	authCfg := config.AuthConfig{
		CookieSecure:   true,
		CookieDomain:   "example.com",
		CookieSameSite: "lax",
		// RefreshTokenCookieName not set, should default to "refresh_token"
	}

	cfg := handler.NewCookieConfig(authCfg)

	if cfg.RefreshTokenCookieName != "refresh_token" {
		t.Errorf("expected RefreshTokenCookieName 'refresh_token', got %s", cfg.RefreshTokenCookieName)
	}
}
