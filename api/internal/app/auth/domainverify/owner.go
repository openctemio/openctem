package domainverify

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
)

// OwnerOfDomain returns the organization that holds the email domain verified
// for SSO: its "home organization" (RFC-058). ok is false when nobody holds
// it, when the domain is not a valid claimable name, and when the claim is
// ambiguous (two verified holders left over from before claims were
// exclusive, flagged claim_conflict): an ambiguous claim manages nobody.
//
// Reads across tenants by design (a claim is platform-wide); callers use the
// answer to classify an address and never show another organization's rows.
func (s *Service) OwnerOfDomain(ctx context.Context, rawDomain string) (owner shared.ID, ok bool, err error) {
	domain, err := verifieddomain.NormalizeDomain(rawDomain)
	if err != nil {
		return shared.ID{}, false, nil //nolint:nilerr // an unparseable domain has no owner
	}
	claims, err := s.repo.ListSSOClaims(ctx, domain)
	if err != nil {
		return shared.ID{}, false, err
	}
	var holder *verifieddomain.VerifiedDomain
	for _, c := range claims {
		if c.Purpose() != verifieddomain.PurposeSSO || !c.IsVerified() {
			continue
		}
		if c.ClaimConflict() || holder != nil {
			return shared.ID{}, false, nil
		}
		holder = c
	}
	if holder == nil {
		return shared.ID{}, false, nil
	}
	return holder.TenantID(), true, nil
}

// OwnsAnySSODomain reports whether an organization holds at least one domain
// verified for SSO.
func OwnsAnySSODomain(ctx context.Context, repo verifieddomain.Repository, tenantID shared.ID) (bool, error) {
	rows, err := repo.ListByTenant(ctx, tenantID)
	if err != nil {
		return false, err
	}
	for _, d := range rows {
		if d.Purpose() == verifieddomain.PurposeSSO && d.IsVerified() {
			return true, nil
		}
	}
	return false, nil
}
