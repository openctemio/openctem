package unit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The sign-up policy at the HTTP edge: a refused registration answers the one
// SIGNUP_NOT_AVAILABLE refusal and writes no account; a mode switch never
// locks out an account that exists; /auth/info follows the policy.

type switchPolicy struct {
	mu sync.Mutex
	p  signupdom.Policy
}

func (s *switchPolicy) Current(context.Context) signupdom.Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.p
}

func (s *switchPolicy) set(m signupdom.Mode) {
	s.mu.Lock()
	s.p = signupdom.Policy{Mode: m}
	s.mu.Unlock()
}

func signupHarness(t *testing.T, mode signupdom.Mode) (*handler.LocalAuthHandler, *authTestDeps, *switchPolicy) {
	t.Helper()
	svc, deps := newTestAuthService()
	pol := &switchPolicy{p: signupdom.Policy{Mode: mode}}
	svc.SetSignupPolicy(pol)
	sess := auth.NewSessionService(deps.sessionRepo, deps.rtRepo, logger.NewNop())
	h := handler.NewLocalAuthHandler(svc, sess, nil, nil, deps.cfg, logger.NewNop())
	h.SetSignupPolicy(pol)
	return h, deps, pol
}

func TestRegister_AdminOnlyRefusesWithoutWritingAnAccount(t *testing.T) {
	h, deps, _ := signupHarness(t, signupdom.ModeAdminOnly)
	rec := postJSON(t, h.Register, map[string]string{"email": "stranger@example.com", "password": "Str0ngPassw0rd!", "name": "S"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["code"] != string(handler.CodeSignupNotAvailable) {
		t.Fatalf("expected code %s, got %s", handler.CodeSignupNotAvailable, rec.Body.String())
	}
	if deps.userRepo.createCalls != 0 || len(deps.userRepo.users) != 0 {
		t.Fatal("a refused registration must not write an account")
	}
}

func TestRegister_SelfServiceCreatesTheAccount(t *testing.T) {
	h, deps, _ := signupHarness(t, signupdom.ModeSelfService)
	rec := postJSON(t, h.Register, map[string]string{"email": "new@example.com", "password": "Str0ngPassw0rd!", "name": "N"})
	if rec.Code != http.StatusCreated || len(deps.userRepo.users) != 1 {
		t.Fatalf("expected the account, got %d %s", rec.Code, rec.Body.String())
	}
}

// Self-service sign-up refuses a disposable-address email, writing nothing.
func TestRegister_SelfServiceRefusesDisposableEmail(t *testing.T) {
	h, deps, _ := signupHarness(t, signupdom.ModeSelfService)
	rec := postJSON(t, h.Register, map[string]string{"email": "x@mailinator.com", "password": "Str0ngPassw0rd!", "name": "X"})
	if rec.Code != http.StatusForbidden || deps.userRepo.createCalls != 0 {
		t.Fatalf("expected a refusal with no account, got %d %s (creates=%d)", rec.Code, rec.Body.String(), deps.userRepo.createCalls)
	}
}

// Switching to admin_only never locks out someone who already has an account.
func TestSignupModeSwitch_ExistingAccountStillSignsIn(t *testing.T) {
	h, _, pol := signupHarness(t, signupdom.ModeSelfService)
	if rec := postJSON(t, h.Register, map[string]string{"email": "early@example.com", "password": "Str0ngPassw0rd!", "name": "E"}); rec.Code != http.StatusCreated {
		t.Fatalf("seed: %d", rec.Code)
	}
	pol.set(signupdom.ModeAdminOnly)
	rec := postJSON(t, h.Login, map[string]string{"email": "early@example.com", "password": "Str0ngPassw0rd!"})
	if rec.Code != http.StatusOK {
		t.Fatalf("an existing account must still sign in after the switch, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestAuthInfo_RegistrationEnabledFollowsThePolicy(t *testing.T) {
	h, _, pol := signupHarness(t, signupdom.ModeAdminOnly)
	read := func() bool {
		rec := httptest.NewRecorder()
		h.Info(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/info", nil))
		var body handler.AuthInfoResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return body.RegistrationEnabled
	}
	if read() {
		t.Fatal("admin_only: registration must be reported off")
	}
	pol.set(signupdom.ModeSelfService)
	if !read() {
		t.Fatal("self_service: registration must be reported on")
	}
}
