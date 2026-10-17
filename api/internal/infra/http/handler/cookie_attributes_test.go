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

// Admin console cookies: the session, MFA and CSRF cookies are HttpOnly and
// scoped to the console API (the session is forced HttpOnly even if a caller
// passes false); the console pages read a copy of the CSRF token scoped to
// /admin, so a tenant page's script never finds it; the old readable copy at
// "/" is cleared. Secure follows the flag and SameSite is always Strict.
func TestAdminConsoleCookieAttributes(t *testing.T) {
	type want struct {
		name, path string
		httpOnly   bool
		cleared    bool
	}
	find := func(t *testing.T, rec *httptest.ResponseRecorder, name, path string) *http.Cookie {
		t.Helper()
		for _, c := range rec.Result().Cookies() {
			if c.Name == name && c.Path == path {
				return c
			}
		}
		t.Fatalf("no %s cookie on path %s", name, path)
		return nil
	}
	check := func(t *testing.T, rec *httptest.ResponseRecorder, secure bool, ws []want) {
		t.Helper()
		for _, w := range ws {
			c := find(t, rec, w.name, w.path)
			if c.Secure != secure || c.HttpOnly != w.httpOnly || c.SameSite != http.SameSiteStrictMode {
				t.Errorf("%s on %s: Secure=%v HttpOnly=%v SameSite=%v; want Secure=%v HttpOnly=%v Strict",
					w.name, w.path, c.Secure, c.HttpOnly, c.SameSite, secure, w.httpOnly)
			}
			if cleared := c.MaxAge < 0; cleared != w.cleared {
				t.Errorf("%s on %s: cleared=%v, want %v", w.name, w.path, cleared, w.cleared)
			}
		}
	}
	for _, secure := range []bool{true, false} {
		h := NewAdminConsoleHandler(nil, secure, logger.NewNop())

		rec := httptest.NewRecorder()
		token, err := h.issueSessionCookies(rec, "session-token")
		if err != nil {
			t.Fatal(err)
		}
		check(t, rec, secure, []want{
			{middleware.AdminSessionCookie, "/api/v1/admin", true, false},
			{middleware.AdminCSRFCookie, "/api/v1/admin", true, false},
			{middleware.AdminCSRFCookie, "/", false, true},
			{middleware.AdminMFACookie, "/api/v1/admin/auth", true, true},
		})
		// The token goes to the response body; the cookie carries the same
		// value for the API's double-submit check.
		if api := find(t, rec, middleware.AdminCSRFCookie, "/api/v1/admin"); token == "" || api.Value != token {
			t.Errorf("the returned token must match the cookie: %q vs %q", token, api.Value)
		}
		// No console cookie is readable by a script: on a second port of the
		// tenant host, the tenant pages share the host's cookies.
		for _, c := range rec.Result().Cookies() {
			if c.MaxAge >= 0 && !c.HttpOnly {
				t.Errorf("%s (path %s) is readable by scripts", c.Name, c.Path)
			}
		}

		rec = httptest.NewRecorder()
		h.setCookie(rec, middleware.AdminSessionCookie, "s", "/api/v1/admin", 60, false)
		check(t, rec, secure, []want{{middleware.AdminSessionCookie, "/api/v1/admin", true, false}})

		rec = httptest.NewRecorder()
		h.clearCSRFCookies(rec)
		check(t, rec, secure, []want{
			{middleware.AdminCSRFCookie, "/api/v1/admin", true, true},
			{middleware.AdminCSRFCookie, "/", false, true},
		})
	}
}
