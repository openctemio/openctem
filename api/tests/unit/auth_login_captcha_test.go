package unit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func postLogin(h *handler.LocalAuthHandler, ip, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
	req.RemoteAddr = ip + ":40000"
	rec := httptest.NewRecorder()
	h.Login(rec, req)
	return rec
}

// After three failed sign-ins from one address, the next attempt from that
// address must pass the CAPTCHA, whatever the account (known or not), and
// even with the right password. Another address is not affected, and a
// passing token lets the sign-in through.
func TestLogin_CaptchaAfterRepeatedFailures(t *testing.T) {
	svc, deps := newTestAuthService()
	sess := auth.NewSessionService(deps.sessionRepo, deps.rtRepo, logger.NewNop())
	h := handler.NewLocalAuthHandler(svc, sess, nil, nil, deps.cfg, logger.NewNop())
	if rec := postJSON(t, h.Register, map[string]string{"email": "known@example.com", "password": "Str0ngPassw0rd!", "name": "K"}); rec.Code != http.StatusCreated {
		t.Fatalf("seed: %d", rec.Code)
	}
	for _, u := range deps.userRepo.users {
		u.VerifyEmail()
	}
	h.SetCaptcha(fakeCaptcha{good: "ok-token"})
	h.SetLoginFailureCounter(handler.NewMemoryLoginFailures())

	const attacker = "203.0.113.9"
	for _, email := range []string{"known@example.com", "nobody@example.com", "known@example.com"} {
		if rec := postLogin(h, attacker, `{"email":"`+email+`","password":"Wrong-Passw0rd!"}`); rec.Code != http.StatusUnauthorized {
			t.Fatalf("a wrong password answers 401, got %d %s", rec.Code, rec.Body.String())
		}
	}
	for _, email := range []string{"known@example.com", "nobody@example.com"} {
		rec := postLogin(h, attacker, `{"email":"`+email+`","password":"Str0ngPassw0rd!"}`)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "CAPTCHA_REQUIRED") {
			t.Fatalf("%s: the fourth attempt needs the CAPTCHA, got %d %s", email, rec.Code, rec.Body.String())
		}
	}
	if rec := postLogin(h, "198.51.100.4", `{"email":"known@example.com","password":"Str0ngPassw0rd!"}`); rec.Code != http.StatusOK {
		t.Fatalf("another address is not affected, got %d %s", rec.Code, rec.Body.String())
	}
	if rec := postLogin(h, attacker, `{"email":"known@example.com","password":"Str0ngPassw0rd!","captcha_token":"ok-token"}`); rec.Code != http.StatusOK {
		t.Fatalf("a passing CAPTCHA lets the sign-in through, got %d %s", rec.Code, rec.Body.String())
	}
	// A success clears the count.
	if rec := postLogin(h, attacker, `{"email":"known@example.com","password":"Str0ngPassw0rd!"}`); rec.Code != http.StatusOK {
		t.Fatalf("after a success no CAPTCHA is asked, got %d %s", rec.Code, rec.Body.String())
	}
}
