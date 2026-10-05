package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// Users and sessions are global: one sign-in is exchangeable for an access
// token in every organization the account belongs to. A federated session is
// exempt from an organization's SSO enforcement and 2FA requirement ONLY when
// that organization's own identity provider issued it. A session from another
// organization's IdP, from social OAuth, or recorded before the issuing
// organization was stored is handled exactly like a password session.

// federate turns a stored (password-login) session into a federated one, as
// the SSO/SAML/OAuth callbacks stamp it. A zero issuer is social OAuth or a
// session recorded before the issuing organization was stored.
func federate(s *session.Session, method session.AuthMethod, issuer shared.ID) {
	s.SetAuthMethod(method)
	s.SetIDPTenant(issuer)
}

func memberOf(roles map[*tenant.Tenant]string) []tenant.UserMembership {
	out := make([]tenant.UserMembership, 0, len(roles))
	for tn, role := range roles {
		out = append(out, tenant.UserMembership{TenantID: tn.ID().String(), TenantSlug: tn.Slug(), TenantName: tn.Name(), Role: role})
	}
	return out
}

func TestFederatedSession_SSOEnforcement_IssuingOrgOnly(t *testing.T) {
	type tc struct {
		name     string
		method   session.AuthMethod
		issuer   string // "A", "B" or "" (social OAuth / legacy)
		target   string // organization the token is requested for
		role     string
		enforced bool
		wantErr  error
		// wantClaim is the auth_method minted into the access token when allowed.
		wantClaim string
	}
	cases := []tc{
		{"org B SAML session -> org A (SSO enforced) refused", session.AuthMethodSAML, "B", "A", "member", true, auth.ErrSSORequired, ""},
		{"org B OIDC session -> org A (SSO enforced) refused", session.AuthMethodSSO, "B", "A", "member", true, auth.ErrSSORequired, ""},
		{"org B SAML session -> org B (SSO enforced) allowed", session.AuthMethodSAML, "B", "B", "member", true, nil, "saml"},
		{"org A own IdP session -> org A (SSO enforced) allowed", session.AuthMethodSSO, "A", "A", "member", true, nil, "sso"},
		{"social OAuth session -> org A (SSO enforced) refused", session.AuthMethodSSO, "", "A", "member", true, auth.ErrSSORequired, ""},
		{"social OAuth session -> org A (not enforced) allowed as password", session.AuthMethodSSO, "", "A", "member", false, nil, "password"},
		{"org B session -> org A (not enforced) allowed as password", session.AuthMethodSAML, "B", "A", "admin", false, nil, "password"},
		{"org B session -> org A OWNER (break-glass) allowed as password", session.AuthMethodSAML, "B", "A", "owner", true, nil, "password"},
	}

	for _, c := range cases {
		for _, op := range []string{"exchange", "refresh"} {
			t.Run(c.name+"/"+op, func(t *testing.T) {
				svc, deps := newTestAuthService()
				orgs := map[string]*tenant.Tenant{
					"A": mustNewEnforcedTenant(t, deps.tenantRepo, "org-a", c.enforced),
					"B": mustNewEnforcedTenant(t, deps.tenantRepo, "org-b", true),
				}
				roles := map[*tenant.Tenant]string{orgs["A"]: "member", orgs["B"]: "member"}
				roles[orgs[c.target]] = c.role
				deps.tenantRepo.userMemberships = memberOf(roles)

				rt, sessID := loginPassword(t, svc, deps, "fed@example.com")
				var issuer shared.ID
				if c.issuer != "" {
					issuer = orgs[c.issuer].ID()
				}
				federate(deps.sessionRepo.sessions[sessID], c.method, issuer)

				target := orgs[c.target].ID().String()
				var access string
				var err error
				if op == "exchange" {
					var res *auth.ExchangeTokenResult
					res, err = svc.ExchangeToken(context.Background(), auth.ExchangeTokenInput{RefreshToken: rt, TenantID: target})
					if res != nil {
						access = res.AccessToken
					}
				} else {
					var res *auth.RefreshTokenResult
					res, err = svc.RefreshToken(context.Background(), auth.RefreshTokenInput{RefreshToken: rt, TenantID: target})
					if res != nil {
						access = res.AccessToken
					}
				}

				if c.wantErr != nil {
					if !errors.Is(err, c.wantErr) {
						t.Fatalf("want %v, got %v", c.wantErr, err)
					}
					return
				}
				if err != nil {
					t.Fatalf("want allowed, got %v", err)
				}
				// The access token's auth_method is the per-request SSO gate's input:
				// it must be federated only for the issuing organization.
				claims, cerr := svc.ValidateAccessToken(access)
				if cerr != nil {
					t.Fatalf("validate access token: %v", cerr)
				}
				if claims.AuthMethod != c.wantClaim {
					t.Fatalf("auth_method claim = %q, want %q", claims.AuthMethod, c.wantClaim)
				}
			})
		}
	}
}

func TestFederatedSession_MFARequirement_IssuingOrgOnly(t *testing.T) {
	setup := func(t *testing.T, enrolled bool) (*mfaHarness, *tenant.Tenant, *tenant.Tenant, *auth.LoginResult) {
		t.Helper()
		h := newMFAHarness(t)
		a := newPolicyTenant(t, h.tenants, "mfa-org-a", false)
		b := newPolicyTenant(t, h.tenants, "mfa-org-b", false)
		h.tenants.userMemberships = memberOf(map[*tenant.Tenant]string{a: "member", b: "member"})
		uid := h.seedUser(t, "fed2fa@example.com")
		res := h.login(t, "fed2fa@example.com")
		if enrolled {
			// The user has 2FA on — exactly what a password session needs to
			// pass. The session under test then goes through the second step.
			secret, _ := h.enroll(t, uid)
			h.forgetLastStep(uid)
			ch := h.login(t, "fed2fa@example.com").MFAChallenge
			var err error
			res, err = h.svc.VerifyMFALogin(context.Background(), auth.VerifyMFAInput{Token: ch.Token, Code: currentCode(t, secret)})
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
		}
		// The 2FA requirement is switched on after sign-in, so the login above
		// did not already demand enrollment.
		for _, tn := range []*tenant.Tenant{a, b} {
			st := tn.TypedSettings()
			st.Security.MFARequired = true
			_ = tn.UpdateSettings(st)
		}
		return h, a, b, res
	}

	t.Run("org B SAML session -> org A requiring 2FA: 2FA required", func(t *testing.T) {
		for _, enrolled := range []bool{false, true} {
			h, a, b, res := setup(t, enrolled)
			federate(h.sessions.sessions[res.SessionID], session.AuthMethodSAML, b.ID())
			_, err := h.svc.ExchangeToken(context.Background(), auth.ExchangeTokenInput{RefreshToken: res.RefreshToken, TenantID: a.ID().String()})
			if !errors.Is(err, auth.ErrMFAEnrollmentRequired) {
				t.Fatalf("enrolled=%v: want ErrMFAEnrollmentRequired, got %v", enrolled, err)
			}
		}
	})

	t.Run("org B SAML session -> org B requiring 2FA: allowed (its IdP owns the factor)", func(t *testing.T) {
		h, _, b, res := setup(t, false)
		federate(h.sessions.sessions[res.SessionID], session.AuthMethodSAML, b.ID())
		if _, err := h.svc.ExchangeToken(context.Background(), auth.ExchangeTokenInput{RefreshToken: res.RefreshToken, TenantID: b.ID().String()}); err != nil {
			t.Fatalf("issuing org must admit its own SSO session, got %v", err)
		}
	})

	t.Run("social OAuth session -> org requiring 2FA: 2FA required", func(t *testing.T) {
		for _, enrolled := range []bool{false, true} {
			h, a, _, res := setup(t, enrolled)
			federate(h.sessions.sessions[res.SessionID], session.AuthMethodSSO, shared.ID{})
			_, err := h.svc.RefreshToken(context.Background(), auth.RefreshTokenInput{RefreshToken: res.RefreshToken, TenantID: a.ID().String()})
			if !errors.Is(err, auth.ErrMFAEnrollmentRequired) {
				t.Fatalf("enrolled=%v: want ErrMFAEnrollmentRequired, got %v", enrolled, err)
			}
		}
	})
}

// The SAML login tail stamps the session as SAML AND issued by the
// organization whose assertion it validated.
func TestCompleteFederatedLogin_StampsIssuingTenant(t *testing.T) {
	sessions := newSSOmockSessionRepo()
	svc := newTestSSOService(newSSOmockIPRepo(), newSSOmockTenantRepo(), newSSOmockUserRepo(),
		sessions, newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())
	svc.SetDomainVerifier(ssoUnitVerifier{"example.com": true})
	tn := createTestTenant("saml-org")

	if _, err := svc.CompleteFederatedLogin(context.Background(), tn, "saml@example.com", "Saml", "member", true); err != nil {
		t.Fatalf("CompleteFederatedLogin: %v", err)
	}
	if len(sessions.sessions) != 1 {
		t.Fatalf("created %d sessions, want 1", len(sessions.sessions))
	}
	for _, s := range sessions.sessions {
		if s.AuthMethod() != session.AuthMethodSAML {
			t.Fatalf("auth method = %q, want saml", s.AuthMethod())
		}
		if !s.IDPTenantID().Equals(tn.ID()) {
			t.Fatalf("issuing tenant = %s, want %s", s.IDPTenantID(), tn.ID())
		}
	}
}

// The domain rule every gate uses.
func TestSession_FederatedFor(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	mk := func(m session.AuthMethod, issuer shared.ID) *session.Session {
		s, err := session.NewWithID(shared.NewID(), shared.NewID(), "tok", "", "", 0)
		if err != nil {
			t.Fatalf("new: %v", err)
		}
		s.SetAuthMethod(m)
		s.SetIDPTenant(issuer)
		return s
	}
	cases := []struct {
		name   string
		s      *session.Session
		tenant string
		want   bool
	}{
		{"own IdP (sso)", mk(session.AuthMethodSSO, a), a.String(), true},
		{"own IdP (saml)", mk(session.AuthMethodSAML, a), a.String(), true},
		{"other org's IdP", mk(session.AuthMethodSAML, b), a.String(), false},
		{"social OAuth / legacy: no issuer", mk(session.AuthMethodSSO, shared.ID{}), a.String(), false},
		{"password session carrying an issuer is still password", mk(session.AuthMethodPassword, a), a.String(), false},
		{"malformed tenant id", mk(session.AuthMethodSSO, a), "not-a-uuid", false},
		{"empty tenant id", mk(session.AuthMethodSSO, a), "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.s.FederatedFor(c.tenant); got != c.want {
				t.Fatalf("FederatedFor = %v, want %v", got, c.want)
			}
			wantMethod := session.AuthMethodPassword
			if c.want {
				wantMethod = c.s.AuthMethod()
			}
			if got := c.s.AuthMethodFor(c.tenant); got != wantMethod {
				t.Fatalf("AuthMethodFor = %q, want %q", got, wantMethod)
			}
		})
	}
}
