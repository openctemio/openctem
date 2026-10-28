package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/crypto"
)

// ResendVerification issues a token only for a local, unverified account that
// was not mailed in the last two minutes; every other case is (nil, nil), so
// the HTTP answer cannot tell the cases apart.
func TestAuthService_ResendVerification(t *testing.T) {
	ctx := context.Background()

	t.Run("unknown address issues nothing", func(t *testing.T) {
		svc, _ := newTestAuthService()
		res, err := svc.ResendVerification(ctx, "nobody@example.com")
		if err != nil || res != nil {
			t.Fatalf("res=%v err=%v", res, err)
		}
	})

	t.Run("verified account issues nothing", func(t *testing.T) {
		svc, deps := newTestAuthService()
		seedAuthLocalUser(deps.userRepo, "ok@example.com", "hash")
		res, err := svc.ResendVerification(ctx, "ok@example.com")
		if err != nil || res != nil {
			t.Fatalf("res=%v err=%v", res, err)
		}
	})

	t.Run("federated account issues nothing", func(t *testing.T) {
		svc, deps := newTestAuthService()
		seedAuthOIDCUser(deps.userRepo, "sso@example.com")
		res, err := svc.ResendVerification(ctx, "sso@example.com")
		if err != nil || res != nil {
			t.Fatalf("res=%v err=%v", res, err)
		}
	})

	t.Run("a link mailed a moment ago is not repeated", func(t *testing.T) {
		svc, deps := newTestAuthService()
		u := seedAuthUnverifiedUser(deps.userRepo, "new@example.com", "hash", "first-token")
		before := *u.EmailVerificationToken()
		res, err := svc.ResendVerification(ctx, "new@example.com")
		if err != nil || res != nil {
			t.Fatalf("within the cooldown: res=%v err=%v", res, err)
		}
		if *u.EmailVerificationToken() != before {
			t.Fatal("the stored token changed inside the cooldown")
		}
	})

	t.Run("an old link is replaced, hash only at rest, old link dead, cap then holds", func(t *testing.T) {
		svc, deps := newTestAuthService()
		u := seedAuthUserWithExpiredVerification(deps.userRepo, "late@example.com", "hash", "old-token")
		res, err := svc.ResendVerification(ctx, "late@example.com")
		if err != nil || res == nil || res.Token == "" {
			t.Fatalf("res=%v err=%v", res, err)
		}
		stored := u.EmailVerificationToken()
		if stored == nil || *stored == res.Token || *stored != crypto.HashToken(res.Token) {
			t.Fatal("the raw token was stored, or the hash does not match the issued token")
		}
		if err := svc.VerifyEmail(ctx, "old-token"); !errors.Is(err, auth.ErrInvalidVerificationToken) {
			t.Fatalf("the previous link still works: %v", err)
		}
		// A second request right after is inside the per-address cap.
		again, err := svc.ResendVerification(ctx, "late@example.com")
		if err != nil || again != nil {
			t.Fatalf("second request: res=%v err=%v", again, err)
		}
		if err := svc.VerifyEmail(ctx, res.Token); err != nil {
			t.Fatalf("the new link does not verify: %v", err)
		}
	})
}

// A reset link works once: the second submit of the same token is refused
// (the repository's conditional UPDATE decides; see the postgres test for the
// concurrent case).
func TestAuthService_ResetPasswordTokenIsSingleUse(t *testing.T) {
	svc, deps := newTestAuthService()
	seedAuthUserWithResetToken(deps.userRepo, "user@example.com", "$2a$04$dummy", "reset-once")
	in := auth.ResetPasswordInput{Token: "reset-once", NewPassword: "NewStrongPassword123!"}
	if err := svc.ResetPassword(context.Background(), in); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := svc.ResetPassword(context.Background(), in); !errors.Is(err, auth.ErrInvalidResetToken) {
		t.Fatalf("second use: %v, want ErrInvalidResetToken", err)
	}
}
