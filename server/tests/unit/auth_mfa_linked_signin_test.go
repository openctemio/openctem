package unit

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/auth"
	"github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/mfa"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
	"github.com/openctemio/openctem/server/pkg/domain/user"
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

// A Google-only account (no password) invited into an organization that
// requires 2FA: its sign-in asks for enrollment, the enrollment opens a session
// that went through our second step, and that session gets the organization's
// token. Its Account > Security status offers the session enrollment and no
// "turn off" (there is no password to confirm that with).
func TestSocialAccount_EnrollsAndEntersTwoFactorOrganization(t *testing.T) {
	ctx := context.Background()
	h := newMFAHarness(t)
	acme := newPolicyTenant(t, h.tenants, "social-2fa", true)
	h.tenants.userMemberships = []tenant.UserMembership{
		{TenantID: acme.ID().String(), TenantSlug: acme.Slug(), TenantName: "Acme", Role: "member"},
	}
	u, err := user.NewOAuthUser("new@example.com", "New", "", user.AuthProviderGoogle)
	if err != nil {
		t.Fatal(err)
	}
	h.users.users[u.ID().String()] = u

	st, err := h.svc.GetMFAStatus(ctx, u.ID().String())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Supported || !st.EnrollThroughSession || st.Enabled || st.CanTurnOff || !st.RequiredByOrganization {
		t.Fatalf("status of a social account before enrollment: %+v", st)
	}

	c, err := h.svc.LinkedSignInChallenge(ctx, u, "203.0.113.7", "test")
	if err != nil || c == nil || c.Purpose != mfa.PurposeEnroll {
		t.Fatalf("want an enrollment challenge, got %+v %v", c, err)
	}
	setup, err := h.svc.BeginMFAEnrollmentFromChallenge(ctx, c.Token)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	done, codes, err := h.svc.CompleteMFAEnrollmentFromChallenge(ctx, auth.CompleteMFAEnrollmentInput{Token: c.Token, Code: currentCode(t, setup.Secret)})
	if err != nil || done.RefreshToken == "" || len(codes) != mfa.RecoveryCodeCount {
		t.Fatalf("complete: %v (codes %d)", err, len(codes))
	}
	if _, err := h.svc.ExchangeToken(ctx, auth.ExchangeTokenInput{RefreshToken: done.RefreshToken, TenantID: acme.ID().String()}); err != nil {
		t.Fatalf("organization token after enrollment: %v", err)
	}
	if !h.audits.has(audit.ActionAuthMFAEnabled) {
		t.Fatal("enrollment not audited")
	}
	if h.notifier.mfaEnabled != 1 {
		t.Fatalf("social enrolment sent %d notices, want 1", h.notifier.mfaEnabled)
	}

	// The next sign-in through the provider asks for the code.
	h.forgetLastStep(u.ID())
	c2, err := h.svc.LinkedSignInChallenge(ctx, u, "", "")
	if err != nil || c2 == nil || c2.Purpose != mfa.PurposeVerify {
		t.Fatalf("want a verify challenge after enrollment, got %+v %v", c2, err)
	}
}
