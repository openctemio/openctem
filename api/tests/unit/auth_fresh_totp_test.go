package unit

import (
	"context"
	"errors"
	"testing"

	authapp "github.com/openctemio/openctem/api/internal/app/auth"
)

// A fresh authenticator code (an owner approving their own scope entry):
// the account must have an authenticator, a password does not count, and a
// code is accepted once.
func TestVerifyFreshTOTP(t *testing.T) {
	ctx := context.Background()

	t.Run("password account has no authenticator", func(t *testing.T) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "p@example.com").String()
		if err := h.svc.VerifyFreshTOTP(ctx, uid, mfaTestPassword); !errors.Is(err, authapp.ErrTOTPNotEnrolled) {
			t.Fatalf("password account: %v", err)
		}
	})

	t.Run("a code is accepted once; recovery codes do not count", func(t *testing.T) {
		h := newMFAHarness(t)
		id := h.seedUser(t, "t@example.com")
		uid := id.String()
		secret, recovery := h.enroll(t, id)
		h.forgetLastStep(id)
		if err := h.svc.VerifyFreshTOTP(ctx, uid, recovery[0]); !errors.Is(err, authapp.ErrStepUpFailed) {
			t.Fatalf("recovery code: %v", err)
		}
		code := currentCode(t, secret)
		if err := h.svc.VerifyFreshTOTP(ctx, uid, code); err != nil {
			t.Fatalf("valid code: %v", err)
		}
		if err := h.svc.VerifyFreshTOTP(ctx, uid, code); !errors.Is(err, authapp.ErrStepUpFailed) {
			t.Fatalf("replayed code: %v", err)
		}
	})
}
