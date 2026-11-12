package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/logger"
)

type denyCaptcha struct{}

func (denyCaptcha) Verify(context.Context, string, string) (bool, error) { return false, nil }

// After LoginCaptchaAfter failures from one address the console sign-in must
// pass the CAPTCHA before the password is looked at (the service is not
// reached: it is nil here, so reaching it would panic).
func TestAdminConsoleLoginAsksCaptchaAfterFailures(t *testing.T) {
	h := NewAdminConsoleHandler(nil, false, logger.NewNop())
	f := NewMemoryLoginFailures()
	h.SetLoginGuard(denyCaptcha{}, f)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/admin/auth/login", strings.NewReader(`{"email":"a@b.c","password":"x"}`))
	r.RemoteAddr = "203.0.113.9:4000"
	key := consoleFailureKey(getClientIP(r))
	for i := 0; i < LoginCaptchaAfter; i++ {
		_ = f.Record(context.Background(), key)
	}
	w := httptest.NewRecorder()
	h.Login(w, r)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), string(CodeCaptchaRequired)) {
		t.Fatalf("got %d %s, want 403 CAPTCHA_REQUIRED", w.Code, w.Body.String())
	}
}
