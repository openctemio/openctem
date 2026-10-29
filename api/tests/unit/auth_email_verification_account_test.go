package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/password"
)

// Email verification is a property of the account. One organization's
// setting must not let an unverified account skip it for the others, and an
// organization may require a verified address only to enter itself.

func seedUnverifiedNoToken(repo *mockAuthUserRepo, email, hash string) *user.User {
	u := user.Reconstitute(shared.NewID(), nil, email, "Unverified", "", "", user.StatusActive,
		user.Preferences{}, nil, time.Now().UTC(), time.Now().UTC(), user.AuthProviderLocal, &hash,
		false, nil, nil, nil, nil, 0, nil)
	repo.users[u.ID().String()] = u
	return u
}

func TestEmailVerification_IsAccountWide(t *testing.T) {
	hash, _ := password.New(password.WithCost(4)).Hash("ValidPassword123")

	t.Run("a tenant set to never does not let an unverified user log in", func(t *testing.T) {
		cfg := defaultAuthTestConfig()
		cfg.RequireEmailVerification = true
		svc, deps := newTestAuthServiceWithConfig(cfg)
		legacy := mustNewTenantWithVerificationMode(t, "Legacy", tenant.EmailVerificationNever)
		other := mustNewTenantWithVerificationMode(t, "Other", tenant.EmailVerificationAuto)
		deps.tenantRepo.tenants[legacy.ID().String()] = legacy
		deps.tenantRepo.tenants[other.ID().String()] = other
		seedUnverifiedNoToken(deps.userRepo, "two@example.com", hash)
		// A member of the "never" organization and of another one.
		deps.tenantRepo.userMemberships = []tenant.UserMembership{
			{TenantID: legacy.ID().String(), Role: "member"},
			{TenantID: other.ID().String(), Role: "member"},
		}
		_, err := svc.Login(context.Background(), auth.LoginInput{Email: "two@example.com", Password: "ValidPassword123"})
		if !errors.Is(err, auth.ErrEmailNotVerified) {
			t.Fatalf("an unverified account must not skip verification because one organization says never: %v", err)
		}
	})

	t.Run("always applies to entering that organization only", func(t *testing.T) {
		cfg := defaultAuthTestConfig() // platform does not require verification
		svc, deps := newTestAuthServiceWithConfig(cfg)
		strict := mustNewTenantWithVerificationMode(t, "Strict", tenant.EmailVerificationAlways)
		legacy := mustNewTenantWithVerificationMode(t, "Legacy", tenant.EmailVerificationNever)
		deps.tenantRepo.tenants[strict.ID().String()] = strict
		deps.tenantRepo.tenants[legacy.ID().String()] = legacy
		seedUnverifiedNoToken(deps.userRepo, "mix@example.com", hash)
		deps.tenantRepo.userMemberships = []tenant.UserMembership{
			{TenantID: strict.ID().String(), Role: "member"},
			{TenantID: legacy.ID().String(), Role: "member"},
		}
		res, err := svc.Login(context.Background(), auth.LoginInput{Email: "mix@example.com", Password: "ValidPassword123"})
		if err != nil {
			t.Fatalf("login follows the platform rule only: %v", err)
		}
		_, err = svc.ExchangeToken(context.Background(), auth.ExchangeTokenInput{RefreshToken: res.RefreshToken, TenantID: strict.ID().String()})
		if !errors.Is(err, auth.ErrEmailNotVerified) {
			t.Fatalf("the organization that requires verified email must refuse entry: %v", err)
		}
		if _, err := svc.ExchangeToken(context.Background(), auth.ExchangeTokenInput{RefreshToken: res.RefreshToken, TenantID: legacy.ID().String()}); err != nil {
			t.Fatalf("the other organization follows the platform: %v", err)
		}
	})

	t.Run("a verified user enters an organization that requires verified email", func(t *testing.T) {
		svc, deps := newTestAuthServiceWithConfig(defaultAuthTestConfig())
		strict := mustNewTenantWithVerificationMode(t, "Strict", tenant.EmailVerificationAlways)
		deps.tenantRepo.tenants[strict.ID().String()] = strict
		seedAuthLocalUser(deps.userRepo, "ok@example.com", hash)
		deps.tenantRepo.userMemberships = []tenant.UserMembership{{TenantID: strict.ID().String(), Role: "member"}}
		res, err := svc.Login(context.Background(), auth.LoginInput{Email: "ok@example.com", Password: "ValidPassword123"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.ExchangeToken(context.Background(), auth.ExchangeTokenInput{RefreshToken: res.RefreshToken, TenantID: strict.ID().String()}); err != nil {
			t.Fatalf("verified user refused: %v", err)
		}
	})
}
