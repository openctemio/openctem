package unit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// POST /auth/logout with the refresh token in the body (how the web signs
// out, server side) ends the session without any access token, and a request
// without a refresh token goes to the access-token sign-out.
func TestLogoutHandler_RefreshTokenInBodyEndsSession(t *testing.T) {
	svc, deps := newTestAuthService()
	rt, sid := loginPassword(t, svc, deps, "idle-handler@example.com")
	h := handler.NewLocalAuthHandler(svc, nil, nil, deps.cfg, logger.NewNop())

	fallbackCalled := false
	fallback := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fallbackCalled = true
		w.WriteHeader(http.StatusUnauthorized)
	})
	logout := h.LogoutWithRefreshToken(fallback)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", strings.NewReader(`{"refresh_token":"`+rt+`"}`))
	rec := httptest.NewRecorder()
	logout(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d %s", rec.Code, rec.Body.String())
	}
	if fallbackCalled {
		t.Fatal("a refresh-token sign-out must not need the access token")
	}
	if deps.sessionRepo.sessions[sid].IsActive() {
		t.Fatal("the session must be revoked")
	}
	if !strings.Contains(strings.Join(rec.Header().Values("Set-Cookie"), ";"), "refresh_token=;") {
		t.Fatalf("the refresh cookie must be cleared, got %v", rec.Header().Values("Set-Cookie"))
	}

	// No refresh token anywhere: the access-token sign-out answers.
	rec = httptest.NewRecorder()
	logout(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil))
	if !fallbackCalled || rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected the access-token sign-out, got called=%v code=%d", fallbackCalled, rec.Code)
	}
}

// A refresh token in the cookie alone is ambient: without the CSRF pair it
// is refused and nothing is revoked (a cross-site page cannot sign a user out).
func TestLogoutHandler_CookieTokenNeedsCSRF(t *testing.T) {
	svc, deps := newTestAuthService()
	rt, sid := loginPassword(t, svc, deps, "cookie@example.com")
	h := handler.NewLocalAuthHandler(svc, nil, nil, deps.cfg, logger.NewNop())
	logout := h.LogoutWithRefreshToken(http.NotFoundHandler())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: rt})
	rec := httptest.NewRecorder()
	logout(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without the CSRF pair, got %d", rec.Code)
	}
	if !deps.sessionRepo.sessions[sid].IsActive() {
		t.Fatal("nothing may be revoked")
	}
}

// Signing out with only the refresh token ends the session. The web used to
// call the API sign-out with the access token alone; after 15 idle minutes
// that cookie is gone, the call was skipped, and the session and its refresh
// chain stayed valid for days after the user "signed out".
func TestAuthService_LogoutByRefreshToken(t *testing.T) {
	t.Run("ends the session of a valid refresh token", func(t *testing.T) {
		svc, deps := newTestAuthService()
		rt, sid := loginPassword(t, svc, deps, "idle@example.com")

		if err := svc.LogoutByRefreshToken(context.Background(), rt); err != nil {
			t.Fatalf("LogoutByRefreshToken: %v", err)
		}
		sess := deps.sessionRepo.sessions[sid]
		if sess == nil || sess.IsActive() {
			t.Fatal("the session must be revoked")
		}
		if deps.rtRepo.revokeBySessionCalls != 1 {
			t.Fatalf("its refresh tokens must be revoked, got %d RevokeBySessionID calls", deps.rtRepo.revokeBySessionCalls)
		}
	})

	t.Run("a forged or unknown token ends nothing", func(t *testing.T) {
		svc, deps := newTestAuthService()
		_, sid := loginPassword(t, svc, deps, "other@example.com")

		for _, tok := range []string{"not-a-jwt", ""} {
			if err := svc.LogoutByRefreshToken(context.Background(), tok); err != nil {
				t.Fatalf("token %q: expected nil, got %v", tok, err)
			}
		}
		if !deps.sessionRepo.sessions[sid].IsActive() {
			t.Fatal("another user's session must stay active")
		}
		if deps.rtRepo.revokeBySessionCalls != 0 {
			t.Fatalf("nothing may be revoked, got %d calls", deps.rtRepo.revokeBySessionCalls)
		}
	})
}
