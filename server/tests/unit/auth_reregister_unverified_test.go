package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/auth"
)

// Registering again with an address whose password account never verified
// tells the caller to email a set-password link. Following that link verifies
// the address and replaces the password, so:
//   - a user whose verification email was lost gets back in;
//   - whoever registered the address first (pre-hijacking) loses the account.
func TestAuthService_ReregisterUnverified(t *testing.T) {
	cfg := defaultAuthTestConfig()
	cfg.RequireEmailVerification = true
	svc, deps := newTestAuthServiceWithConfig(cfg)
	ctx := context.Background()

	// Someone registers the address first with their own password.
	first, err := svc.Register(ctx, auth.RegisterInput{Email: "owner@example.com", Password: "AttackerChose123!", Name: "X"})
	if err != nil || first.User == nil || !first.RequiresVerification {
		t.Fatalf("first registration: %+v %v", first, err)
	}

	// The real owner registers: same constant answer, plus the flag.
	again, err := svc.Register(ctx, auth.RegisterInput{Email: "owner@example.com", Password: "OwnerChose456!", Name: "Owner"})
	if err != nil {
		t.Fatalf("second registration: %v", err)
	}
	if !again.EmailExisted || !again.ExistingUnverified || again.User != nil {
		t.Fatalf("expected the existing-unverified signal and no account, got %+v", again)
	}

	// The handler emails a set-password link (forgot-password); the owner follows it.
	fp, err := svc.ForgotPassword(ctx, auth.ForgotPasswordInput{Email: "owner@example.com"})
	if err != nil || fp.Token == "" {
		t.Fatalf("ForgotPassword: %+v %v", fp, err)
	}
	if err := svc.ResetPassword(ctx, auth.ResetPasswordInput{Token: fp.Token, NewPassword: "OwnerChose456!"}); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	if _, err := svc.Login(ctx, auth.LoginInput{Email: "owner@example.com", Password: "AttackerChose123!"}); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("the first registrant's password must no longer work, got %v", err)
	}
	if _, err := svc.Login(ctx, auth.LoginInput{Email: "owner@example.com", Password: "OwnerChose456!"}); err != nil {
		t.Fatalf("the owner must sign in (address verified by the link), got %v", err)
	}
	_ = deps
}

// A verified account, and a new address, never get the flag.
func TestAuthService_ReregisterVerifiedOrNew_NoLink(t *testing.T) {
	svc, deps := newTestAuthService()
	seedAuthLocalUser(deps.userRepo, "verified@example.com", "$2a$04$dummy") // verified

	for _, email := range []string{"verified@example.com", "brand-new@example.com"} {
		res, err := svc.Register(context.Background(), auth.RegisterInput{Email: email, Password: "SomePassword123!", Name: "N"})
		if err != nil {
			t.Fatalf("%s: %v", email, err)
		}
		if res.ExistingUnverified {
			t.Fatalf("%s: no set-password link may be sent", email)
		}
	}
}
