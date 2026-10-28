package unit

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// One identity (RFC-134): the account a platform administrator signs in to the
// console with also signs in on the main site, where it is an ordinary user.
// The main-site sign-in knows nothing about the platform role (no gate, no
// flag in the answer), and the console's own password check still accepts the
// account. The console's second factor and session stay separate (tested in
// the console handler and middleware tests).
func TestLogin_PlatformAdminAccountSignsInOnMainSite(t *testing.T) {
	svc, deps := newTestAuthService()
	sess := auth.NewSessionService(deps.sessionRepo, deps.rtRepo, logger.NewNop())
	h := handler.NewLocalAuthHandler(svc, sess, nil, deps.cfg, logger.NewNop())
	if rec := postJSON(t, h.Register, map[string]string{"email": "root@example.com", "password": "Str0ngPassw0rd!", "name": "N"}); rec.Code != http.StatusCreated {
		t.Fatalf("seed: %d", rec.Code)
	}
	for _, u := range deps.userRepo.users {
		u.VerifyEmail()
	}

	rec := postLogin(h, "203.0.113.5", `{"email":"root@example.com","password":"Str0ngPassw0rd!"}`)
	if rec.Code != http.StatusOK || len(rec.Header().Values("Set-Cookie")) == 0 {
		t.Fatalf("the administrator's account signs in on the main site, got %d %s", rec.Code, rec.Body.String())
	}
	for _, leak := range []string{"platform_admin", "super_admin", "ops_admin", "platform_role"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Fatalf("the main-site answer must not carry %q: %s", leak, rec.Body.String())
		}
	}

	// The console's own first factor is a separate check on the same account.
	if u, err := svc.VerifyConsolePassword(context.Background(), "root@example.com", "Str0ngPassw0rd!", "203.0.113.8", "test"); err != nil || u == nil {
		t.Fatalf("the console must still accept the administrator's password: %v", err)
	}
}
