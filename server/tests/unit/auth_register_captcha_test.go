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

type fakeCaptcha struct{ good string }

func (f fakeCaptcha) Verify(_ context.Context, token, _ string) (bool, error) {
	return token != "" && token == f.good, nil
}

func postRegister(h *handler.LocalAuthHandler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.Register(rec, req)
	return rec
}

// With a CAPTCHA configured, registration needs a passing token. It is
// checked before the account lookup, so a missing or wrong token gets the
// same answer for a new and an existing email, and nothing is created.
func TestRegister_CaptchaRequiredWhenConfigured(t *testing.T) {
	svc, deps := newTestAuthService()
	seedAuthLocalUser(deps.userRepo, "existing@example.com", "$2a$04$dummy")
	h := handler.NewLocalAuthHandler(svc, nil, nil, deps.cfg, logger.NewNop())
	h.SetCaptcha(fakeCaptcha{good: "ok-token"})

	var bodies []string
	for _, email := range []string{"existing@example.com", "new@example.com"} {
		for _, tok := range []string{"", "wrong"} {
			rec := postRegister(h, `{"email":"`+email+`","password":"Zr7uqLakeTunnel41","name":"N","captcha_token":"`+tok+`"}`)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "CAPTCHA_FAILED") {
				t.Fatalf("%s token=%q: expected 400 CAPTCHA_FAILED, got %d %s", email, tok, rec.Code, rec.Body.String())
			}
			bodies = append(bodies, rec.Body.String())
		}
	}
	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Fatalf("answers differ:\n%s\n%s", bodies[0], b)
		}
	}
	if deps.userRepo.createCalls != 0 {
		t.Fatalf("nothing may be created, got %d", deps.userRepo.createCalls)
	}

	rec := postRegister(h, `{"email":"new@example.com","password":"Zr7uqLakeTunnel41","name":"N","captcha_token":"ok-token"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("a passing token registers, got %d %s", rec.Code, rec.Body.String())
	}
}

// Without a CAPTCHA configured, registration works as before (no token).
func TestRegister_NoCaptchaConfigured(t *testing.T) {
	svc, deps := newTestAuthService()
	h := handler.NewLocalAuthHandler(svc, nil, nil, deps.cfg, logger.NewNop())
	if rec := postRegister(h, `{"email":"a@example.com","password":"Zr7uqLakeTunnel41","name":"N"}`); rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d %s", rec.Code, rec.Body.String())
	}
}
