package domainverify

import (
	"context"
	"errors"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
)

// DomainJITPolicy returns whether SSO may admit new people on emailDomain in
// tenantID and the role they get ("" = the identity provider's default).
// Only a verified SSO domain of the tenant admits anyone (fail closed).
func (s *Service) DomainJITPolicy(ctx context.Context, tenantID, emailDomain string) (enabled bool, role string, err error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return false, "", nil //nolint:nilerr // a malformed id admits nobody
	}
	domain, err := verifieddomain.NormalizeDomain(emailDomain)
	if err != nil {
		return false, "", nil //nolint:nilerr // a malformed domain admits nobody
	}
	vd, err := s.repo.GetByTenantAndDomain(ctx, tid, domain)
	if errors.Is(err, verifieddomain.ErrNotFound) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	if !vd.AdmitsSSO() {
		return false, "", nil
	}
	on, r := vd.JIT()
	return on, r, nil
}

// ChangeJIT changes a domain's just-in-time provisioning (platform
// administrator, RFC-058).
func (s *Service) ChangeJIT(ctx context.Context, tenantID, id shared.ID, enabled bool, role string) (*verifieddomain.VerifiedDomain, error) {
	vd, err := s.repo.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if err := vd.ChangeJIT(enabled, role); err != nil {
		return nil, err
	}
	if err := s.repo.Update(ctx, vd); err != nil {
		return nil, err
	}
	return vd, nil
}

// IsLapsedSSODomain reports whether an organization held the domain verified
// for SSO, lost the proof, and nobody holds it now: its mailboxes may have
// changed hands (an expired domain re-registered), so a reset link mailed
// there proves nothing.
func (s *Service) IsLapsedSSODomain(ctx context.Context, rawDomain string) (bool, error) {
	domain, err := verifieddomain.NormalizeDomain(rawDomain)
	if err != nil {
		return false, nil //nolint:nilerr // not a claimable domain: never lapsed
	}
	claims, err := s.repo.ListSSOClaims(ctx, domain)
	if err != nil {
		return false, err
	}
	lapsed := false
	for _, c := range claims {
		if c.Purpose() != verifieddomain.PurposeSSO {
			continue
		}
		if c.IsVerified() {
			return false, nil
		}
		if c.LapsedAt() != nil {
			lapsed = true
		}
	}
	return lapsed, nil
}
