package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// cookieByName returns the Set-Cookie entry with the given name.
func cookieByName(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no Set-Cookie for %q (got %v)", name, rec.Result().Header.Values("Set-Cookie"))
	return nil
}

// Session cookies set by the shared helpers: Secure follows
// AUTH_COOKIE_SECURE, the credentials are HttpOnly, the tenant hint is
// deliberately JS-readable, and SameSite is the configured policy.
func TestSessionCookieAttributes(t *testing.T) {
	for _, secure := range []bool{true, false} {
		cfg := NewCookieConfig(config.AuthConfig{CookieSecure: secure, CookieSameSite: "strict"})
		exp := time.Now().Add(time.Hour)

		rec := httptest.NewRecorder()
		SetRefreshTokenCookie(rec, "r", exp, cfg)
		SetAccessTokenCookie(rec, "a", exp, cfg)
		SetTenantCookie(rec, "t-id", "t-slug", "owner", cfg)

		for _, tc := range []struct {
			name     string
			httpOnly bool
		}{
			{"refresh_token", true},
			{"auth_token", true},
			{DefaultTenantCookieName, false},
		} {
			c := cookieByName(t, rec, tc.name)
			if c.Secure != secure {
				t.Errorf("secure=%v: %s Secure=%v", secure, tc.name, c.Secure)
			}
			if c.HttpOnly != tc.httpOnly {
				t.Errorf("%s HttpOnly=%v, want %v", tc.name, c.HttpOnly, tc.httpOnly)
			}
			if c.SameSite != http.SameSiteStrictMode {
				t.Errorf("%s SameSite=%v, want Strict", tc.name, c.SameSite)
			}
		}

		rec = httptest.NewRecorder()
		ClearRefreshTokenCookie(rec, cfg)
		ClearTenantCookie(rec, cfg)
		if c := cookieByName(t, rec, "refresh_token"); c.Secure != secure || !c.HttpOnly {
			t.Errorf("cleared refresh cookie Secure=%v HttpOnly=%v", c.Secure, c.HttpOnly)
		}
		if c := cookieByName(t, rec, DefaultTenantCookieName); c.Secure != secure {
			t.Errorf("cleared tenant cookie Secure=%v", c.Secure)
		}
	}
}

// Admin console cookies: admin_session and admin_mfa are HttpOnly (session is
// forced even if a caller passes false), admin_csrf is the JS-readable
// double-submit token, Secure follows the flag and SameSite is always Strict.
func TestAdminConsoleCookieAttributes(t *testing.T) {
	for _, secure := range []bool{true, false} {
		h := NewAdminConsoleHandler(nil, secure, "", logger.NewNop())
		rec := httptest.NewRecorder()
		h.setCookie(rec, middleware.AdminSessionCookie, "s", "/api/v1/admin", 60, false)
		h.setCookie(rec, middleware.AdminMFACookie, "m", "/api/v1/admin/auth", 60, true)
		h.setCookie(rec, middleware.AdminCSRFCookie, "c", "/", 60, false)

		for _, tc := range []struct {
			name     string
			httpOnly bool
		}{
			{middleware.AdminSessionCookie, true},
			{middleware.AdminMFACookie, true},
			{middleware.AdminCSRFCookie, false},
		} {
			c := cookieByName(t, rec, tc.name)
			if c.Secure != secure {
				t.Errorf("secure=%v: %s Secure=%v", secure, tc.name, c.Secure)
			}
			if c.HttpOnly != tc.httpOnly {
				t.Errorf("%s HttpOnly=%v, want %v", tc.name, c.HttpOnly, tc.httpOnly)
			}
			if c.SameSite != http.SameSiteStrictMode {
				t.Errorf("%s SameSite=%v, want Strict", tc.name, c.SameSite)
			}
		}
	}
}
