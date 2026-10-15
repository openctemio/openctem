package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// A privileged member from outside the organization must prove a second
// factor at every token mint, even when the organization requires 2FA from
// nobody (RFC-095 §4.2). A non-privileged outside member and an internal
// administrator are not affected by this rule.
func TestOutsidePrivilegedMemberNeedsSecondFactor(t *testing.T) {
	setup := func(t *testing.T, role tenant.Role, external bool) (*mfaHarness, *tenant.Tenant, string, shared.ID) {
		h := newMFAHarness(t)
		tn := newPolicyTenant(t, h.tenants, "outside-"+string(role), false)
		st := tn.TypedSettings()
		st.Security.MFARequiredForAdmins = false
		st.Security.PersonalAccounts = tenant.PersonalAccountsAllowed // isolate this rule from the personal-account one
		_ = tn.UpdateSettings(st)
		email := string(role) + "@gmail.com"
		h.tenants.userMemberships = []tenant.UserMembership{{TenantID: tn.ID().String(), TenantSlug: tn.Slug(), TenantName: "Acme", Role: string(role)}}
		uid := h.seedUser(t, email)
		ms, _ := tenant.NewMembership(uid, tn.ID(), role, nil)
		if external {
			if err := ms.Classify(tenant.Classification{Kind: tenant.MemberKindExternal, Domain: "gmail.com", Personal: true, EndOptional: true},
				tenant.ExternalAccess{}, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
		h.tenants.memberships = append(h.tenants.memberships, ms)
		return h, tn, email, uid
	}

	t.Run("outside admin without 2FA is refused", func(t *testing.T) {
		h, tn, email, _ := setup(t, tenant.RoleAdmin, true)
		res := h.login(t, email)
		_, err := h.svc.ExchangeToken(context.Background(), auth.ExchangeTokenInput{RefreshToken: res.RefreshToken, TenantID: tn.ID().String()})
		if !errors.Is(err, auth.ErrMFAEnrollmentRequired) {
			t.Fatalf("want ErrMFAEnrollmentRequired, got %v", err)
		}
	})

	t.Run("outside admin with 2FA passes", func(t *testing.T) {
		h, tn, email, uid := setup(t, tenant.RoleAdmin, true)
		secret, _ := h.enroll(t, uid)
		h.forgetLastStep(uid)
		ch := h.login(t, email).MFAChallenge
		res, err := h.svc.VerifyMFALogin(context.Background(), auth.VerifyMFAInput{Token: ch.Token, Code: currentCode(t, secret)})
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if _, err := h.svc.ExchangeToken(context.Background(), auth.ExchangeTokenInput{RefreshToken: res.RefreshToken, TenantID: tn.ID().String()}); err != nil {
			t.Fatalf("outside admin with 2FA refused: %v", err)
		}
	})

	t.Run("outside member and internal admin are not affected", func(t *testing.T) {
		for _, c := range []struct {
			role     tenant.Role
			external bool
		}{{tenant.RoleMember, true}, {tenant.RoleAdmin, false}} {
			h, tn, email, _ := setup(t, c.role, c.external)
			res := h.login(t, email)
			if _, err := h.svc.ExchangeToken(context.Background(), auth.ExchangeTokenInput{RefreshToken: res.RefreshToken, TenantID: tn.ID().String()}); err != nil {
				t.Fatalf("%s external=%v refused: %v", c.role, c.external, err)
			}
		}
	})
}
