package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// A person with an account and no organization holds an account-only token,
// which reaches POST /tenants (it is on the account allow-list). On a
// self-hosted installation (SIGNUP_MODE=disabled, the default) the call must
// still be refused: only a platform administrator creates organizations
// there. The token is not what grants creation; the policy is.
func TestTenantCreate_AccountOnlyTokenFollowsPolicy(t *testing.T) {
	gen := jwt.NewGenerator(jwt.TokenConfig{Secret: "account-only-create-secret-0123456789abcd", Issuer: "test",
		AccessTokenDuration: time.Hour, RefreshTokenDuration: time.Hour})
	token, _, err := gen.GenerateAccessToken(uuid.NewString(), uuid.NewString(), "user")
	if err != nil {
		t.Fatal(err)
	}
	auth := middleware.UnifiedAuth(middleware.UnifiedAuthConfig{Provider: config.AuthProviderLocal, LocalValidator: gen, Logger: logger.NewNop()})

	call := func(configure func(*TenantHandler)) *httptest.ResponseRecorder {
		h := NewTenantHandler(nil, validator.New(), logger.NewNop())
		configure(h)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants", strings.NewReader(`{"name":"X","slug":"x-org"}`))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		auth(http.HandlerFunc(h.Create)).ServeHTTP(rec, req)
		return rec
	}

	// A console policy that says self-service, under the self-hosted ceiling
	// (SIGNUP_MODE=disabled): the ceiling clamps it to admin_only.
	stored := signupdom.Policy{Mode: signupdom.ModeSelfService, Accounts: signupdom.AccountsOpen}
	for name, configure := range map[string]func(*TenantHandler){
		"nothing configured": func(*TenantHandler) {},
		"SIGNUP_MODE=disabled, no console policy": func(h *TenantHandler) {
			h.SetSelfServiceTenantCreation(config.AuthConfig{SignupMode: config.SignupModeDisabled}.SignupOpen())
		},
		"console policy self_service under a disabled ceiling": func(h *TenantHandler) {
			h.SetSignupPolicy(signupdom.Static(signupdom.CeilingDisabled.Clamp(stored)))
		},
		"console policy self_service under a domain ceiling": func(h *TenantHandler) {
			h.SetSignupPolicy(signupdom.Static(signupdom.CeilingDomain.Clamp(stored)))
		},
	} {
		if rec := call(configure); rec.Code != http.StatusForbidden {
			t.Errorf("%s: account-only token got %d %s, want 403", name, rec.Code, rec.Body.String())
		}
	}

	// Control: where the policy allows it, the same token is not refused by
	// the policy (this handler has no user, so it stops at 401 afterwards).
	rec := call(func(h *TenantHandler) {
		h.SetSignupPolicy(signupdom.Static(signupdom.CeilingOpen.Clamp(stored)))
	})
	if rec.Code == http.StatusForbidden {
		t.Fatalf("control: an open installation refused creation: %s", rec.Body.String())
	}
}
