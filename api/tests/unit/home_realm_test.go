package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/domain/orgtrust"
	"github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// Home-realm sign-in (RFC-058): an external member of host A whose home is B
// may use a session issued by B's identity provider as an SSO sign-in of A,
// only when A trusts B (accepted), B still holds the member's domain, and
// (when required) the provider proved a second factor. Never a third
// organization's sign-in, never a password session.

type fakeTrusts struct{ t *orgtrust.Trust }

func (f fakeTrusts) GetPair(_ context.Context, host, home shared.ID) (*orgtrust.Trust, error) {
	if f.t == nil || f.t.HostTenantID != host || f.t.HomeTenantID != home {
		return nil, orgtrust.ErrNotFound
	}
	return f.t, nil
}

type fakeHomeOwners map[string]shared.ID

func (f fakeHomeOwners) OwnerOfDomain(_ context.Context, d string) (shared.ID, bool, error) {
	id, ok := f[d]
	return id, ok, nil
}

type homeRealmCase struct {
	name        string
	issuer      string // "B" (home), "C" (third org), "A" (host), "" (password)
	trustActive bool
	noTrust     bool
	acceptSSO   bool
	requireMFA  bool
	mfaEvidence bool
	homeOwnsDom bool
	internal    bool
	wantErr     error
	wantClaim   string
}

func runHomeRealm(t *testing.T, c homeRealmCase) {
	t.Helper()
	svc, deps := newTestAuthService()
	a := mustNewEnforcedTenant(t, deps.tenantRepo, "host-a", true)
	b := mustNewEnforcedTenant(t, deps.tenantRepo, "home-b", true)
	cOrg := mustNewEnforcedTenant(t, deps.tenantRepo, "third-c", true)
	orgs := map[string]*tenant.Tenant{"A": a, "B": b, "C": cOrg}
	deps.tenantRepo.userMemberships = memberOf(map[*tenant.Tenant]string{a: "member"})

	// The member of A, homed in B.
	m, _ := tenant.NewMembership(shared.NewID(), a.ID(), tenant.RoleMember, nil)
	home := b.ID()
	kind := tenant.MemberKindExternal
	if c.internal {
		kind = tenant.MemberKindInternal
	}
	if err := m.Classify(tenant.Classification{Kind: kind, HomeTenantID: &home, Domain: "partner.example"}, tenant.ExternalAccess{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	deps.tenantRepo.membershipByTenant = map[string]*tenant.Membership{a.ID().String(): m}

	var trust *orgtrust.Trust
	if !c.noTrust {
		settings := orgtrust.DefaultSettings()
		settings.AcceptHomeSSO = c.acceptSSO
		settings.RequireMFAEvidence = c.requireMFA
		trust, _ = orgtrust.New(a.ID(), b.ID(), settings, shared.NewID())
		if c.trustActive {
			_ = trust.Accept(shared.NewID(), false, time.Now())
		}
	}
	owners := fakeHomeOwners{}
	if c.homeOwnsDom {
		owners["partner.example"] = b.ID()
	}
	svc.SetHomeRealm(fakeTrusts{t: trust}, owners)

	rt, sessID := loginPassword(t, svc, deps, "nam@partner.example")
	if c.issuer != "" {
		federate(deps.sessionRepo.sessions[sessID], session.AuthMethodSSO, orgs[c.issuer].ID())
	}
	deps.sessionRepo.sessions[sessID].SetMFAEvidence(c.mfaEvidence)

	res, err := svc.ExchangeToken(context.Background(), auth.ExchangeTokenInput{RefreshToken: rt, TenantID: a.ID().String()})
	if c.wantErr != nil {
		if !errors.Is(err, c.wantErr) {
			t.Fatalf("want %v, got %v", c.wantErr, err)
		}
		return
	}
	if err != nil {
		t.Fatalf("want allowed, got %v", err)
	}
	claims, cerr := svc.ValidateAccessToken(res.AccessToken)
	if cerr != nil {
		t.Fatal(cerr)
	}
	if claims.AuthMethod != c.wantClaim {
		t.Fatalf("auth_method = %q, want %q", claims.AuthMethod, c.wantClaim)
	}
}

func TestHomeRealm_SSOEnforcedHost(t *testing.T) {
	ok := homeRealmCase{issuer: "B", trustActive: true, acceptSSO: true, homeOwnsDom: true, wantClaim: "sso"}
	cases := []func(homeRealmCase) homeRealmCase{
		func(c homeRealmCase) homeRealmCase { c.name = "trusted home sign-in accepted"; return c },
		func(c homeRealmCase) homeRealmCase {
			c.name, c.issuer, c.wantErr = "third organization sign-in refused", "C", auth.ErrSSORequired
			return c
		},
		func(c homeRealmCase) homeRealmCase {
			c.name, c.issuer, c.wantErr = "password session refused", "", auth.ErrSSORequired
			return c
		},
		func(c homeRealmCase) homeRealmCase {
			c.name, c.trustActive, c.wantErr = "trust not accepted yet refused", false, auth.ErrSSORequired
			return c
		},
		func(c homeRealmCase) homeRealmCase {
			c.name, c.noTrust, c.wantErr = "no trust refused", true, auth.ErrSSORequired
			return c
		},
		func(c homeRealmCase) homeRealmCase {
			c.name, c.acceptSSO, c.wantErr = "trust without home sign-in refused", false, auth.ErrSSORequired
			return c
		},
		func(c homeRealmCase) homeRealmCase {
			c.name, c.homeOwnsDom, c.wantErr = "home lost the domain refused", false, auth.ErrSSORequired
			return c
		},
		func(c homeRealmCase) homeRealmCase {
			c.name, c.requireMFA, c.wantErr = "MFA evidence required and missing refused", true, auth.ErrSSORequired
			return c
		},
		func(c homeRealmCase) homeRealmCase {
			c.name, c.requireMFA, c.mfaEvidence = "MFA evidence required and present accepted", true, true
			return c
		},
		func(c homeRealmCase) homeRealmCase {
			c.name, c.internal, c.wantErr = "an internal member gets nothing from a home trust", true, auth.ErrSSORequired
			return c
		},
	}
	for _, mk := range cases {
		c := mk(ok)
		t.Run(c.name, func(t *testing.T) { runHomeRealm(t, c) })
	}
}

// A host requiring 2FA accepts the home sign-in only with MFA evidence or the
// home's attestation.
func TestHomeRealm_MFARequiredHost(t *testing.T) {
	for _, tc := range []struct {
		name     string
		evidence bool
		attests  bool
		want     error
	}{
		{"no evidence, no attestation refused", false, false, auth.ErrMFAEnrollmentRequired},
		{"evidence accepted", true, false, nil},
		{"home attestation accepted", false, true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newMFAHarness(t)
			a := newPolicyTenant(t, h.tenants, "mfa-host", false)
			b := newPolicyTenant(t, h.tenants, "mfa-home", false)
			h.tenants.userMemberships = memberOf(map[*tenant.Tenant]string{a: "member"})
			h.seedUser(t, "nam2@partner.example")
			res := h.login(t, "nam2@partner.example")
			st := a.TypedSettings()
			st.Security.MFARequired = true
			_ = a.UpdateSettings(st)

			m, _ := tenant.NewMembership(shared.NewID(), a.ID(), tenant.RoleMember, nil)
			home := b.ID()
			_ = m.Classify(tenant.Classification{Kind: tenant.MemberKindExternal, HomeTenantID: &home, Domain: "partner.example"}, tenant.ExternalAccess{}, time.Now())
			h.tenants.membershipByTenant = map[string]*tenant.Membership{a.ID().String(): m}
			trust, _ := orgtrust.New(a.ID(), b.ID(), orgtrust.DefaultSettings(), shared.NewID())
			_ = trust.Accept(shared.NewID(), tc.attests, time.Now())
			h.svc.SetHomeRealm(fakeTrusts{t: trust}, fakeHomeOwners{"partner.example": b.ID()})

			sess := h.sessions.sessions[res.SessionID]
			federate(sess, session.AuthMethodSSO, b.ID())
			sess.SetMFAEvidence(tc.evidence)
			_, err := h.svc.ExchangeToken(context.Background(), auth.ExchangeTokenInput{RefreshToken: res.RefreshToken, TenantID: a.ID().String()})
			if !errors.Is(err, tc.want) && !(tc.want == nil && err == nil) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}
