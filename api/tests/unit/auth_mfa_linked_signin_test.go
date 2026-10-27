package unit

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/domain/mfa"
)

// A password account signed into through a linked Google, GitHub or Microsoft
// identity takes the second step its password sign-in takes: with a factor on,
// a verify challenge that the usual second step completes; with none (and no
// organization requiring one), nothing.
func TestLinkedSignInChallenge_SameAsPasswordSignIn(t *testing.T) {
	ctx := context.Background()

	t.Run("factor on: verify challenge, finished by the usual second step", func(t *testing.T) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "linked@gmail.com")
		secret, _ := h.enroll(t, uid)
		h.forgetLastStep(uid)
		u, err := h.users.GetByID(ctx, uid)
		if err != nil {
			t.Fatal(err)
		}
		c, err := h.svc.LinkedSignInChallenge(ctx, u, "203.0.113.7", "test")
		if err != nil {
			t.Fatalf("challenge: %v", err)
		}
		if c == nil || c.Purpose != mfa.PurposeVerify || c.Token == "" {
			t.Fatalf("want a verify challenge, got %+v", c)
		}
		res, err := h.svc.VerifyMFALogin(ctx, auth.VerifyMFAInput{Token: c.Token, Code: currentCode(t, secret)})
		if err != nil {
			t.Fatalf("second step: %v", err)
		}
		if res.RefreshToken == "" {
			t.Fatal("no session after the second step")
		}
	})

	t.Run("no factor and no organization policy: nothing to ask", func(t *testing.T) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "plain@gmail.com")
		u, _ := h.users.GetByID(ctx, uid)
		c, err := h.svc.LinkedSignInChallenge(ctx, u, "", "")
		if err != nil || c != nil {
			t.Fatalf("want no challenge, got %+v %v", c, err)
		}
	})
}
