package unit

import (
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
	h := handler.NewLocalAuthHandler(svc, nil, nil, nil, deps.cfg, logger.NewNop())

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
	h := handler.NewLocalAuthHandler(svc, nil, nil, nil, deps.cfg, logger.NewNop())
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
