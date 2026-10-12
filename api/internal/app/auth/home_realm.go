package auth

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/orgtrust"
	sessiondom "github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Home-realm sign-in for external members (RFC-058).
//
// A session counts as an SSO sign-in of an organization when that
// organization's own identity provider issued it (Session.FederatedFor). For
// an external member it also counts when the member's HOME organization's
// identity provider issued it, and only when all of these hold:
//
//   - the member is an active external member of the host, homed there;
//   - the host trusts that home and the home accepted (an active trust that
//     accepts home sign-in);
//   - the home still holds the member's email domain (a lapsed or transferred
//     domain manages nobody);
//   - when the trust requires it, the provider proved a second factor.
//
// Never weaker than the host: a password session, a social login or a third
// organization's identity provider never counts. For the host's 2FA
// requirement the home sign-in counts only with MFA evidence on the session or
// the home owner's attestation that its identity provider enforces MFA.

// TrustLookup reads the trust host → home.
type TrustLookup interface {
	GetPair(ctx context.Context, host, home shared.ID) (*orgtrust.Trust, error)
}

// HomeDomainOwnerLookup answers which organization holds an email domain
// verified for SSO.
type HomeDomainOwnerLookup interface {
	OwnerOfDomain(ctx context.Context, domain string) (shared.ID, bool, error)
}

// SetHomeRealm wires home-realm sign-in for external members. Without it a
// session counts only for the organization whose identity provider issued it.
func (s *AuthService) SetHomeRealm(trusts TrustLookup, owners HomeDomainOwnerLookup) {
	s.homeTrusts = trusts
	s.homeOwners = owners
}

// assuranceAt reports whether sess is an SSO sign-in of tenantID for userID
// (federated) and whether a second factor is established for it (mfa). Any
// lookup failure answers "not federated" (fail closed).
func (s *AuthService) assuranceAt(ctx context.Context, sess *sessiondom.Session, userID shared.ID, tenantID string) (federated, mfa bool) {
	if sess == nil {
		return false, false
	}
	if sess.FederatedFor(tenantID) {
		return true, true
	}
	if s.homeTrusts == nil || s.homeOwners == nil || s.tenantRepo == nil || !sess.AuthMethod().IsFederated() {
		return false, false
	}
	host, err := shared.IDFromString(tenantID)
	if err != nil {
		return false, false
	}
	m, err := s.tenantRepo.GetMembership(ctx, userID, host)
	if err != nil || m == nil || !m.IsActive() || !m.IsExternal() || m.HomeTenantID() == nil {
		return false, false
	}
	home := *m.HomeTenantID()
	if !sess.FederatedFor(home.String()) {
		return false, false
	}
	trust, err := s.homeTrusts.GetPair(ctx, host, home)
	if err != nil || !trust.IsActive() || !trust.Settings.AcceptHomeSSO {
		return false, false
	}
	owner, ok, err := s.homeOwners.OwnerOfDomain(ctx, m.HomeDomain())
	if err != nil || !ok || owner != home {
		return false, false
	}
	if trust.Settings.RequireMFAEvidence && !sess.MFAEvidence() {
		return false, false
	}
	return true, sess.MFAEvidence() || trust.HomeAttestsMFA
}

// authMethodAt is the auth_method a token for tenantID carries: sso when the
// session is an SSO sign-in of that organization (its own IdP, or a trusted
// home organization's for an external member), the session's method seen
// from outside otherwise.
func (s *AuthService) authMethodAt(ctx context.Context, sess *sessiondom.Session, userID shared.ID, tenantID string) sessiondom.AuthMethod {
	if fed, _ := s.assuranceAt(ctx, sess, userID, tenantID); fed && !sess.FederatedFor(tenantID) {
		return sessiondom.AuthMethodSSO
	}
	return sess.AuthMethodFor(tenantID)
}
