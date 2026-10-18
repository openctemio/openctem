package unit

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// adminGate marks the accounts (by id) that are platform administrators.
type adminGate map[string]bool

func (g adminGate) IsPlatformAdmin(_ context.Context, id shared.ID) bool { return g[id.String()] }

// A platform administrator never signs in on the main site: with the right
// password the answer is the wrong-password one (so the endpoint says nothing
// about which emails are administrators) and no cookie is set. Another user
// still signs in, and the console's own password check still accepts the
// administrator.
func TestLogin_PlatformAdminRefusedOnMainSite(t *testing.T) {
	svc, deps := newTestAuthService()
	sess := auth.NewSessionService(deps.sessionRepo, deps.rtRepo, logger.NewNop())
	h := handler.NewLocalAuthHandler(svc, sess, nil, deps.cfg, logger.NewNop())
	for _, email := range []string{"root@example.com", "member@example.com"} {
		if rec := postJSON(t, h.Register, map[string]string{"email": email, "password": "Str0ngPassw0rd!", "name": "N"}); rec.Code != http.StatusCreated {
			t.Fatalf("seed %s: %d", email, rec.Code)
		}
	}
	gate := adminGate{}
	for _, u := range deps.userRepo.users {
		u.VerifyEmail()
		if u.Email() == "root@example.com" {
			gate[u.ID().String()] = true
		}
	}
	svc.SetPlatformAdminGate(gate)

	admin := postLogin(h, "203.0.113.5", `{"email":"root@example.com","password":"Str0ngPassw0rd!"}`)
	wrong := postLogin(h, "203.0.113.6", `{"email":"member@example.com","password":"Wrong-Passw0rd!"}`)
	if admin.Code != http.StatusUnauthorized || admin.Code != wrong.Code || admin.Body.String() != wrong.Body.String() {
		t.Fatalf("administrator must get the wrong-password answer:\nadmin: %d %s\nwrong: %d %s",
			admin.Code, admin.Body.String(), wrong.Code, wrong.Body.String())
	}
	if c := admin.Header().Values("Set-Cookie"); len(c) != 0 {
		t.Fatalf("no cookie for a refused administrator, got %v", c)
	}
	if strings.Contains(admin.Body.String(), "platform_admin") {
		t.Fatalf("the answer must not mention platform administrators: %s", admin.Body.String())
	}

	if rec := postLogin(h, "203.0.113.7", `{"email":"member@example.com","password":"Str0ngPassw0rd!"}`); rec.Code != http.StatusOK || len(rec.Header().Values("Set-Cookie")) == 0 {
		t.Fatalf("a normal user still signs in, got %d %s", rec.Code, rec.Body.String())
	}

	// The console's own first factor does not go through the main-site path.
	if u, err := svc.VerifyConsolePassword(context.Background(), "root@example.com", "Str0ngPassw0rd!", "203.0.113.8", "test"); err != nil || u == nil {
		t.Fatalf("the console must still accept the administrator's password: %v", err)
	}
}

// A session or refresh token held by an account that became an administrator
// stops working on the main site's token exchange.
func TestExchangeToken_PlatformAdminRefused(t *testing.T) {
	svc, deps := newTestAuthService()
	sess := auth.NewSessionService(deps.sessionRepo, deps.rtRepo, logger.NewNop())
	h := handler.NewLocalAuthHandler(svc, sess, nil, deps.cfg, logger.NewNop())
	if rec := postJSON(t, h.Register, map[string]string{"email": "later@example.com", "password": "Str0ngPassw0rd!", "name": "N"}); rec.Code != http.StatusCreated {
		t.Fatalf("seed: %d", rec.Code)
	}
	var uid string
	for _, u := range deps.userRepo.users {
		u.VerifyEmail()
		uid = u.ID().String()
	}
	res, err := svc.Login(context.Background(), auth.LoginInput{Email: "later@example.com", Password: "Str0ngPassw0rd!"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	svc.SetPlatformAdminGate(adminGate{uid: true})
	_, err = svc.ExchangeToken(context.Background(), auth.ExchangeTokenInput{RefreshToken: res.RefreshToken, TenantID: shared.NewID().String()})
	if !errors.Is(err, session.ErrRefreshTokenRevoked) {
		t.Fatalf("exchange for an administrator must be refused, got %v", err)
	}
}
