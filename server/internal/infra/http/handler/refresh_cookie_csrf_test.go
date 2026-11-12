package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// /auth/token, /auth/refresh, /auth/create-first-team and
// /invitations/accept-with-refresh are authenticated by the refresh
// token. Taken from the refresh_token cookie it is an ambient credential, so
// it now needs the double-submit CSRF pair; a token in the body is not
// ambient and needs nothing.
func TestRefreshTokenFrom_CookieNeedsCSRF(t *testing.T) {
	h := &LocalAuthHandler{logger: logger.NewNop(), cookieConfig: CookieConfig{RefreshTokenCookieName: "refresh_token"}}
	req := func(cookies, header string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(`{}`))
		if cookies != "" {
			r.Header.Set("Cookie", cookies)
		}
		if header != "" {
			r.Header.Set("X-CSRF-Token", header)
		}
		return r
	}

	cases := []struct {
		name, body, cookies, header string
		wantTok                     string
		wantOK                      bool
	}{
		{"body token, no csrf", "rt-body", "", "", "rt-body", true},
		{"body token wins over cookie", "rt-body", "refresh_token=rt-cookie", "", "rt-body", true},
		{"cookie without csrf pair", "", "refresh_token=rt-cookie", "", "", false},
		{"cookie with csrf cookie but no header", "", "refresh_token=rt-cookie; csrf_token=abc", "", "", false},
		{"cookie with mismatched header", "", "refresh_token=rt-cookie; csrf_token=abc", "xyz", "", false},
		{"cookie with matching pair", "", "refresh_token=rt-cookie; csrf_token=abc", "abc", "rt-cookie", true},
		{"no token at all", "", "", "", "", true},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		tok, ok := h.refreshTokenFrom(rec, req(tc.cookies, tc.header), tc.body)
		if tok != tc.wantTok || ok != tc.wantOK {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", tc.name, tok, ok, tc.wantTok, tc.wantOK)
		}
		if !ok && rec.Code != http.StatusForbidden {
			t.Errorf("%s: refused with %d, want 403", tc.name, rec.Code)
		}
	}
}
