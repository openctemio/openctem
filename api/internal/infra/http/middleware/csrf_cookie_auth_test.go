package middleware

// CSRF for requests authenticated by the auth_token cookie.
//
// The auth_token cookie is an ambient credential: a browser attaches it to
// any request the page did not write itself. A state-changing request
// authenticated by it must therefore carry the double-submit CSRF token, on
// every route, whether or not the csrf_token cookie happens to be present.
// A request authenticated by an Authorization header is not ambient (a
// cross-site page cannot set that header without a CORS preflight), so
// Bearer and API-key clients keep working without a CSRF token.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func cookieAuthTestSetup(t *testing.T) (func(http.Handler) http.Handler, string) {
	t.Helper()
	gen := jwt.NewGenerator(jwt.TokenConfig{
		Secret:               "csrf-cookie-auth-test-secret-0123456789abcdef",
		Issuer:               "test",
		AccessTokenDuration:  time.Hour,
		RefreshTokenDuration: time.Hour,
	})
	tok, _, err := gen.GenerateAccessToken("0a0e0c09-5e75-4556-8a26-c8de3ded5d73", "sid", "user")
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	mw := UnifiedAuth(UnifiedAuthConfig{
		Provider:       config.AuthProviderLocal,
		LocalValidator: gen,
		Logger:         logger.New(logger.Config{Level: "error"}),
	})
	return mw, tok
}

type authReq struct {
	method     string
	bearer     string
	authCookie string
	csrfCookie string
	csrfHeader string
}

func (a authReq) build() *http.Request {
	r := httptest.NewRequest(a.method, "/api/v1/users/me", nil)
	if a.bearer != "" {
		r.Header.Set("Authorization", "Bearer "+a.bearer)
	}
	if a.authCookie != "" {
		r.AddCookie(&http.Cookie{Name: DefaultAccessTokenCookieName, Value: a.authCookie})
	}
	if a.csrfCookie != "" {
		r.AddCookie(&http.Cookie{Name: CSRFTokenCookieName, Value: a.csrfCookie})
	}
	if a.csrfHeader != "" {
		r.Header.Set(CSRFHeaderName, a.csrfHeader)
	}
	return r
}

func TestUnifiedAuth_CookieAuth_StateChange_RequiresCSRF(t *testing.T) {
	mw, tok := cookieAuthTestSetup(t)
	cases := []struct {
		name string
		req  authReq
		want int
	}{
		// The exploit: cookie session, no CSRF material at all.
		{"cookie POST no csrf", authReq{method: http.MethodPost, authCookie: tok}, http.StatusForbidden},
		{"cookie PUT no csrf", authReq{method: http.MethodPut, authCookie: tok}, http.StatusForbidden},
		{"cookie PATCH no csrf", authReq{method: http.MethodPatch, authCookie: tok}, http.StatusForbidden},
		{"cookie DELETE no csrf", authReq{method: http.MethodDelete, authCookie: tok}, http.StatusForbidden},
		{"cookie POST header only", authReq{method: http.MethodPost, authCookie: tok, csrfHeader: "abc"}, http.StatusForbidden},
		{"cookie POST cookie only", authReq{method: http.MethodPost, authCookie: tok, csrfCookie: "abc"}, http.StatusForbidden},
		{"cookie POST mismatch", authReq{method: http.MethodPost, authCookie: tok, csrfCookie: "abc", csrfHeader: "abd"}, http.StatusForbidden},
		// Legitimate cookie session.
		{"cookie POST matching csrf", authReq{method: http.MethodPost, authCookie: tok, csrfCookie: "abc", csrfHeader: "abc"}, http.StatusOK},
		{"cookie GET no csrf", authReq{method: http.MethodGet, authCookie: tok}, http.StatusOK},
		{"cookie HEAD no csrf", authReq{method: http.MethodHead, authCookie: tok}, http.StatusOK},
		{"cookie OPTIONS no csrf", authReq{method: http.MethodOptions, authCookie: tok}, http.StatusOK},
		// Header-authenticated clients are not ambient.
		{"bearer POST no csrf", authReq{method: http.MethodPost, bearer: tok}, http.StatusOK},
		{"bearer POST + cookie, no csrf", authReq{method: http.MethodPost, bearer: tok, authCookie: tok}, http.StatusOK},
		// Unauthenticated stays 401, not 403: CSRF is checked after the token.
		{"bad cookie POST no csrf", authReq{method: http.MethodPost, authCookie: "garbage"}, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			mw(okHandler()).ServeHTTP(rr, tc.req.build())
			if rr.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %q)", rr.Code, tc.want, rr.Body.String())
			}
		})
	}
}

// CSRFOptional sits on the tenant route chains after UnifiedAuth. When the
// request was authenticated by the cookie it must not fall open just
// because the csrf_token cookie is absent.
func TestCSRFOptional_CookieAuthenticated_FailsClosed(t *testing.T) {
	_, tok := cookieAuthTestSetup(t)
	chain := func(h http.Handler) http.Handler {
		// Mark the request the way UnifiedAuth does, without its own check,
		// to exercise CSRFOptional on its own.
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r.WithContext(withCookieAuth(r.Context())))
		})
	}
	opt := CSRFOptional(testCSRFConfig())

	rr := httptest.NewRecorder()
	chain(opt(okHandler())).ServeHTTP(rr, authReq{method: http.MethodPost, authCookie: tok}.build())
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cookie-authenticated POST without csrf: status = %d, want 403", rr.Code)
	}

	rr = httptest.NewRecorder()
	chain(opt(okHandler())).ServeHTTP(rr, authReq{method: http.MethodPost, authCookie: tok, csrfCookie: "x", csrfHeader: "x"}.build())
	if rr.Code != http.StatusOK {
		t.Fatalf("cookie-authenticated POST with csrf: status = %d, want 200", rr.Code)
	}

	// Not cookie-authenticated, no csrf cookie: unchanged pass-through.
	rr = httptest.NewRecorder()
	opt(okHandler()).ServeHTTP(rr, authReq{method: http.MethodPost, bearer: tok}.build())
	if rr.Code != http.StatusOK {
		t.Fatalf("bearer POST: status = %d, want 200", rr.Code)
	}
}

// The access-token cookie name follows AUTH_ACCESS_TOKEN_COOKIE_NAME (the web
// sets the cookie under NEXT_PUBLIC_AUTH_COOKIE_NAME); the WebSocket upgrade
// reaches the API with it (RFC-045). The default name is not accepted then.
func TestUnifiedAuth_ConfiguredCookieName(t *testing.T) {
	gen := jwt.NewGenerator(jwt.TokenConfig{
		Secret: "csrf-cookie-auth-test-secret-0123456789abcdef", Issuer: "test",
		AccessTokenDuration: time.Hour, RefreshTokenDuration: time.Hour,
	})
	tok, _, err := gen.GenerateAccessToken("0a0e0c09-5e75-4556-8a26-c8de3ded5d73", "sid", "user")
	if err != nil {
		t.Fatal(err)
	}
	mw := UnifiedAuth(UnifiedAuthConfig{
		Provider: config.AuthProviderLocal, LocalValidator: gen,
		Logger: logger.New(logger.Config{Level: "error"}), CookieName: "kc_auth_token",
	})
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsCookieAuthenticated(r.Context()) {
			t.Error("cookie request not marked cookie-authenticated")
		}
		w.WriteHeader(http.StatusOK)
	}))
	for name, want := range map[string]int{"kc_auth_token": http.StatusOK, DefaultAccessTokenCookieName: http.StatusUnauthorized} {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/ws/", nil)
		r.AddCookie(&http.Cookie{Name: name, Value: tok})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != want {
			t.Errorf("cookie %q: status %d, want %d", name, rec.Code, want)
		}
	}
}
