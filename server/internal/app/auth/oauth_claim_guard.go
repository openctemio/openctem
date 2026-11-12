package auth

import (
	"context"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
)

// ClaimMembershipSource lists an account's organization memberships, active
// and suspended (the tenant repository satisfies it).
type ClaimMembershipSource interface {
	GetUserMembershipsWithStatus(ctx context.Context, userID shared.ID) (*tenantdom.UserMembershipsByStatus, error)
}

// SetClaimGuard wires the check that runs before a social sign-in adopts a
// claimable account (local, no password yet). Without it no such account is
// adopted (fail-closed).
func (s *OAuthService) SetClaimGuard(members ClaimMembershipSource, domains DomainVerifier) {
	s.claimMembers = members
	s.claimDomains = domains
}

// claimVouched reports whether a claimable account may be adopted by a social
// sign-in for email. A passwordless account is created on someone's behalf (an
// organization's SCIM, administrator or just-in-time provisioning), and each of
// those paths requires the organization to have DNS-verified the email domain.
// An account that sits in an organization that never proved the domain was
// created or attached without that proof (for example by SCIM before the
// verified-domain rule): adopting it would sign the address's real owner into
// that organization. Such an account is refused, so the provisioning
// organization cannot capture the person's identity.
//
// Every membership (active or suspended; a suspended one can be reactivated)
// must belong to an organization that verified the domain. An account with no
// membership is vouched: there is no organization to land in. Any lookup
// error, or a missing guard, fails closed.
func (s *OAuthService) claimVouched(ctx context.Context, u *userdom.User, email string) bool {
	if s.claimMembers == nil || s.claimDomains == nil {
		return false
	}
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return false
	}
	domain := email[at+1:]
	ms, err := s.claimMembers.GetUserMembershipsWithStatus(ctx, u.ID())
	if err != nil {
		s.logger.Warn("oauth claim check: memberships unreadable (fail-closed)", "user_id", u.ID().String(), "error", err)
		return false
	}
	if ms == nil {
		return true
	}
	for _, list := range [][]tenantdom.UserMembership{ms.Active, ms.Suspended} {
		for _, m := range list {
			ok, verr := s.claimDomains.IsVerifiedDomain(ctx, m.TenantID, domain)
			if verr != nil {
				s.logger.Warn("oauth claim check: verified-domain lookup failed (fail-closed)", "tenant_id", m.TenantID, "error", verr)
				return false
			}
			if !ok {
				s.logger.Warn("OAuth login blocked: claimable account belongs to an organization that has not verified the email domain",
					"user_id", u.ID().String(), "tenant_id", m.TenantID)
				return false
			}
		}
	}
	return true
}
