package domainverify

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
)

// Sign-up policy of verified SSO domains (docs/rfcs/RFC-104): what an
// organization's claim on its domain does to accounts on it.

// ErrSSORequiredNeedsSSO is returned when sso_required is asked for an
// organization without a usable SSO sign-in (nobody on the domain could sign
// up or in).
var ErrSSORequiredNeedsSSO = fmt.Errorf("%w: requiring SSO needs a working SSO connection for the organization", shared.ErrValidation)

// SetSSOReadiness wires the check that an organization has a usable SSO
// sign-in.
func (s *Service) SetSSOReadiness(f func(ctx context.Context, tenantID shared.ID) (bool, error)) {
	s.ssoReady = f
}

// ChangeSignupPolicy sets the sign-up policy of one of the organization's
// verified SSO domains (tenant-scoped: another organization's domain id is
// not found). notifyCapture reports that existing accounts on the domain must
// now be told the organization manages it.
func (s *Service) ChangeSignupPolicy(ctx context.Context, tenantID, id shared.ID, p verifieddomain.SignupPolicy) (vd *verifieddomain.VerifiedDomain, notifyCapture bool, err error) {
	vd, err = s.repo.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, false, err
	}
	if p.SSORequired {
		ready := false
		if s.ssoReady != nil {
			if ready, err = s.ssoReady(ctx, tenantID); err != nil {
				return nil, false, err
			}
		}
		if !ready {
			return nil, false, ErrSSORequiredNeedsSSO
		}
	}
	notifyCapture, err = vd.ChangeSignupPolicy(p)
	if err != nil {
		return nil, false, err
	}
	if err := s.repo.Update(ctx, vd); err != nil {
		return nil, false, err
	}
	return vd, notifyCapture, nil
}

// SignupPolicyForEmail returns the sign-up policy that governs email. ok is
// false when no organization holds the address's domain unambiguously: a
// claim that is not verified, not for SSO, or in conflict has no effect
// (a lapsed claim stops every effect at once). The exact domain wins over a
// parent claimed with include_subdomains.
//
// Reads across tenants by design (a claim is platform-wide); callers use the
// answer to admit or route an address and never show another organization's
// rows to a client.
func (s *Service) SignupPolicyForEmail(ctx context.Context, email string) (verifieddomain.EmailPolicy, bool, error) {
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return verifieddomain.EmailPolicy{}, false, nil
	}
	domain, err := verifieddomain.NormalizeDomain(email[at+1:])
	if err != nil {
		return verifieddomain.EmailPolicy{}, false, nil //nolint:nilerr // not a claimable domain: no policy
	}
	for candidate, exact := domain, true; ; exact = false {
		holder, err := s.unambiguousHolder(ctx, candidate)
		if err != nil {
			return verifieddomain.EmailPolicy{}, false, err
		}
		if holder != nil && (exact || holder.SignupPolicy().IncludeSubdomains) {
			return verifieddomain.EmailPolicy{
				OrganizationID: holder.TenantID(), DomainID: holder.ID(),
				Domain: holder.Domain(), Policy: holder.SignupPolicy(),
			}, true, nil
		}
		dot := strings.IndexByte(candidate, '.')
		parent := candidate[dot+1:]
		if dot < 0 || !strings.Contains(parent, ".") {
			return verifieddomain.EmailPolicy{}, false, nil
		}
		candidate = parent
	}
}

// unambiguousHolder returns the single verified SSO claim of domain, or nil.
func (s *Service) unambiguousHolder(ctx context.Context, domain string) (*verifieddomain.VerifiedDomain, error) {
	claims, err := s.repo.ListSSOClaims(ctx, domain)
	if err != nil {
		return nil, err
	}
	var holder *verifieddomain.VerifiedDomain
	for _, c := range claims {
		if !c.AdmitsSSO() {
			continue
		}
		if c.ClaimConflict() || holder != nil {
			return nil, nil
		}
		holder = c
	}
	return holder, nil
}
