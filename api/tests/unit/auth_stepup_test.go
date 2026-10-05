package unit

import (
	"context"
	"errors"
	"testing"

	authapp "github.com/openctemio/openctem/api/internal/app/auth"
)

// Step-up re-authentication (RFC-052 D-2): TOTP when enrolled (never a
// recovery code, never a replayed step), else the password; failures count
// towards the lockout.
func TestStepUp(t *testing.T) {
	ctx := context.Background()

	t.Run("password account without TOTP needs the password", func(t *testing.T) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "p@example.com").String()
		if m, _ := h.svc.StepUpMethodFor(ctx, uid); m != authapp.StepUpPassword {
			t.Fatalf("method %q", m)
		}
		if err := h.svc.VerifyStepUp(ctx, uid, "", authapp.StepUpProof{}); !errors.Is(err, authapp.ErrStepUpRequired) {
			t.Fatalf("no proof: %v", err)
		}
		if err := h.svc.VerifyStepUp(ctx, uid, "", authapp.StepUpProof{Password: "wrong-password"}); !errors.Is(err, authapp.ErrStepUpFailed) {
			t.Fatalf("wrong password: %v", err)
		}
		if err := h.svc.VerifyStepUp(ctx, uid, "", authapp.StepUpProof{Password: mfaTestPassword}); err != nil {
			t.Fatalf("right password: %v", err)
		}
	})

	t.Run("TOTP account needs a fresh code; password and recovery codes do not count", func(t *testing.T) {
		h := newMFAHarness(t)
		id := h.seedUser(t, "t@example.com")
		uid := id.String()
		secret, recovery := h.enroll(t, id)
		h.forgetLastStep(id)
		if m, _ := h.svc.StepUpMethodFor(ctx, uid); m != authapp.StepUpTOTP {
			t.Fatalf("method %q", m)
		}
		if err := h.svc.VerifyStepUp(ctx, uid, "", authapp.StepUpProof{Password: mfaTestPassword}); !errors.Is(err, authapp.ErrStepUpRequired) {
			t.Fatalf("password instead of TOTP: %v", err)
		}
		if err := h.svc.VerifyStepUp(ctx, uid, "", authapp.StepUpProof{TOTP: recovery[0]}); !errors.Is(err, authapp.ErrStepUpFailed) {
			t.Fatalf("recovery code: %v", err)
		}
		code := currentCode(t, secret)
		if err := h.svc.VerifyStepUp(ctx, uid, "", authapp.StepUpProof{TOTP: code}); err != nil {
			t.Fatalf("valid code: %v", err)
		}
		if err := h.svc.VerifyStepUp(ctx, uid, "", authapp.StepUpProof{TOTP: code}); !errors.Is(err, authapp.ErrStepUpFailed) {
			t.Fatalf("replayed code: %v", err)
		}
	})

	t.Run("failures lock the account", func(t *testing.T) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "l@example.com").String()
		var err error
		for range 20 {
			err = h.svc.VerifyStepUp(ctx, uid, "", authapp.StepUpProof{Password: "wrong-password"})
			if errors.Is(err, authapp.ErrAccountLocked) {
				break
			}
		}
		if !errors.Is(err, authapp.ErrAccountLocked) {
			t.Fatalf("no lockout after repeated failures: %v", err)
		}
		if err := h.svc.VerifyStepUp(ctx, uid, "", authapp.StepUpProof{Password: mfaTestPassword}); err == nil {
			t.Fatal("a locked account passed step-up")
		}
	})
}
