package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/auth"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// Personal accounts (RFC-058): blocked refuses, allowed_with_mfa needs a
// second factor; an SSO exception lets a named member in, with a second
// factor, while SSO is enforced.

func personalMember(t *testing.T, tn *tenant.Tenant) *tenant.Membership {
	t.Helper()
	m, _ := tenant.NewMembership(shared.NewID(), tn.ID(), tenant.RoleViewer, nil)
	until := time.Now().Add(24 * time.Hour)
	if err := m.Classify(tenant.Classification{Kind: tenant.MemberKindExternal, Domain: "gmail.com", Personal: true},
		tenant.ExternalAccess{ExpiresAt: &until}, time.Now()); err != nil {
		t.Fatal(err)
	}
	return m
}

func setSecurity(t *testing.T, tn *tenant.Tenant, f func(*tenant.SecuritySettings)) {
	t.Helper()
	st := tn.TypedSettings()
	f(&st.Security)
	if err := tn.UpdateSettings(st); err != nil {
		t.Fatal(err)
	}
}

func TestPersonalPolicy_AtTokenMint(t *testing.T) {
	for _, tc := range []struct {
		name     string
		policy   tenant.PersonalAccountsPolicy
		enrolled bool
		want     error
	}{
		{"allowed", tenant.PersonalAccountsAllowed, false, nil},
		{"blocked", tenant.PersonalAccountsBlocked, true, auth.ErrPersonalAccountsBlocked},
		{"with MFA, no second factor", tenant.PersonalAccountsAllowedWithMFA, false, auth.ErrMFAEnrollmentRequired},
		{"with MFA, second factor on", tenant.PersonalAccountsAllowedWithMFA, true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newMFAHarness(t)
			a := newPolicyTenant(t, h.tenants, "personal-host", false)
			h.tenants.userMemberships = memberOf(map[*tenant.Tenant]string{a: "viewer"})
			uid := h.seedUser(t, "jdoe@gmail.com")
			res := h.login(t, "jdoe@gmail.com")
			if tc.enrolled {
				secret, _ := h.enroll(t, uid)
				h.forgetLastStep(uid)
				ch := h.login(t, "jdoe@gmail.com").MFAChallenge
				var err error
				res, err = h.svc.VerifyMFALogin(context.Background(), auth.VerifyMFAInput{Token: ch.Token, Code: currentCode(t, secret)})
				if err != nil {
					t.Fatal(err)
				}
			}
			setSecurity(t, a, func(s *tenant.SecuritySettings) { s.PersonalAccounts = tc.policy })
			h.tenants.membershipByTenant = map[string]*tenant.Membership{a.ID().String(): personalMember(t, a)}

			_, err := h.svc.ExchangeToken(context.Background(), auth.ExchangeTokenInput{RefreshToken: res.RefreshToken, TenantID: a.ID().String()})
			if tc.want == nil && err != nil {
				t.Fatalf("want allowed, got %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func TestSSOException_AtTokenMint(t *testing.T) {
	for _, tc := range []struct {
		name      string
		exception bool
		expired   bool
		enrolled  bool
		want      error
	}{
		{"no exception refused", false, false, true, auth.ErrSSORequired},
		{"exception without a second factor refused", true, false, false, auth.ErrSSORequired},
		{"expired exception refused", true, true, true, auth.ErrSSORequired},
		{"exception with a second factor allowed", true, false, true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newMFAHarness(t)
			a := newPolicyTenant(t, h.tenants, "sso-host", false)
			h.tenants.userMemberships = memberOf(map[*tenant.Tenant]string{a: "member"})
			// The membership the token-mint gates read (a new organization
			// asks its owners and admins for a second factor, so the role is
			// looked up; a member is not asked).
			vendor, _ := tenant.NewMembership(shared.NewID(), a.ID(), tenant.RoleMember, nil)
			h.tenants.membershipByTenant = map[string]*tenant.Membership{a.ID().String(): vendor}
			uid := h.seedUser(t, "vendor@partner.example")
			res := h.login(t, "vendor@partner.example")
			if tc.enrolled {
				secret, _ := h.enroll(t, uid)
				h.forgetLastStep(uid)
				ch := h.login(t, "vendor@partner.example").MFAChallenge
				var err error
				res, err = h.svc.VerifyMFALogin(context.Background(), auth.VerifyMFAInput{Token: ch.Token, Code: currentCode(t, secret)})
				if err != nil {
					t.Fatal(err)
				}
			}
			setSecurity(t, a, func(s *tenant.SecuritySettings) {
				s.SSOEnforced = true
				if tc.exception {
					at := time.Now().Add(24 * time.Hour)
					if tc.expired {
						at = time.Now().Add(-time.Minute)
					}
					s.SSOExceptions = []tenant.SSOException{{UserID: uid.String(), Reason: "vendor", ExpiresAt: at}}
				}
			})
			_, err := h.svc.ExchangeToken(context.Background(), auth.ExchangeTokenInput{RefreshToken: res.RefreshToken, TenantID: a.ID().String()})
			if tc.want == nil && err != nil {
				t.Fatalf("want allowed, got %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func TestPersonalPolicy_BlockedRefusesInvitation(t *testing.T) {
	svc, _, host, _ := newExternalTenantService(t)
	setSecurity(t, host, func(s *tenant.SecuritySettings) { s.PersonalAccounts = tenant.PersonalAccountsBlocked })
	_, err := svc.CreateInvitation(context.Background(), host.ID().String(), tenantapp.CreateInvitationInput{
		Email: "j.doe@gmail.com", Role: "member", RoleIDs: []string{viewerRoleID},
	}, shared.NewID(), audit.AuditContext{})
	if !errors.Is(err, tenantapp.ErrPersonalAccountsBlocked) {
		t.Fatalf("want ErrPersonalAccountsBlocked, got %v", err)
	}
	// A work address is unaffected.
	if _, err := svc.CreateInvitation(context.Background(), host.ID().String(), tenantapp.CreateInvitationInput{
		Email: "x@mssp.vn", Role: "member", RoleIDs: []string{viewerRoleID},
	}, shared.NewID(), audit.AuditContext{}); err != nil {
		t.Fatalf("work address: %v", err)
	}
}
