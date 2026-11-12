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

// bgGate marks the accounts (by id) linked to a break-glass administrator.
type bgGate map[string]bool

func (g bgGate) IsBreakGlass(_ context.Context, id shared.ID) bool { return g[id.String()] }

// A break-glass account never signs in on the main site: with the right
// password the answer is the wrong-password one (no account enumeration), no
// cookie is set. A regular platform administrator's account still signs in.
func TestLogin_BreakGlassRefusedOnMainSite(t *testing.T) {
	svc, deps := newTestAuthService()
	sess := auth.NewSessionService(deps.sessionRepo, deps.rtRepo, logger.NewNop())
	h := handler.NewLocalAuthHandler(svc, sess, nil, deps.cfg, logger.NewNop())
	for _, email := range []string{"glass@example.com", "admin@example.com", "member@example.com"} {
		if rec := postJSON(t, h.Register, map[string]string{"email": email, "password": "Str0ngPassw0rd!", "name": "N"}); rec.Code != http.StatusCreated {
			t.Fatalf("seed %s: %d", email, rec.Code)
		}
	}
	gate := bgGate{}
	for _, u := range deps.userRepo.users {
		u.VerifyEmail()
		if u.Email() == "glass@example.com" {
			gate[u.ID().String()] = true
		}
	}
	svc.SetBreakGlassGate(gate)

	glass := postLogin(h, "203.0.113.5", `{"email":"glass@example.com","password":"Str0ngPassw0rd!"}`)
	wrong := postLogin(h, "203.0.113.6", `{"email":"member@example.com","password":"Wrong-Passw0rd!"}`)
	if glass.Code != http.StatusUnauthorized || glass.Code != wrong.Code || glass.Body.String() != wrong.Body.String() {
		t.Fatalf("break-glass must get the wrong-password answer:\nglass: %d %s\nwrong: %d %s",
			glass.Code, glass.Body.String(), wrong.Code, wrong.Body.String())
	}
	if c := glass.Header().Values("Set-Cookie"); len(c) != 0 {
		t.Fatalf("no cookie for a refused break-glass account, got %v", c)
	}
	// A regular administrator account (not flagged) and a member sign in.
	for i, email := range []string{"admin@example.com", "member@example.com"} {
		rec := postLogin(h, "203.0.113.1"+string(rune('0'+i)), `{"email":"`+email+`","password":"Str0ngPassw0rd!"}`)
		if rec.Code != http.StatusOK || len(rec.Header().Values("Set-Cookie")) == 0 {
			t.Fatalf("%s must sign in, got %d %s", email, rec.Code, rec.Body.String())
		}
	}
}

// A session held by an account that became break-glass stops working on the
// token exchange and on refresh.
func TestExchangeAndRefresh_BreakGlassRefused(t *testing.T) {
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
	svc.SetBreakGlassGate(bgGate{uid: true})
	tid := shared.NewID().String()
	if _, err = svc.ExchangeToken(context.Background(), auth.ExchangeTokenInput{RefreshToken: res.RefreshToken, TenantID: tid}); !errors.Is(err, session.ErrRefreshTokenRevoked) {
		t.Fatalf("exchange for a break-glass account must be refused, got %v", err)
	}
	if _, err = svc.RefreshToken(context.Background(), auth.RefreshTokenInput{RefreshToken: res.RefreshToken, TenantID: tid}); !errors.Is(err, session.ErrRefreshTokenRevoked) {
		t.Fatalf("refresh for a break-glass account must be refused, got %v", err)
	}
}
