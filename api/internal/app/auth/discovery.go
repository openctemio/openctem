package auth

import (
	"context"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Email-first sign-in (home-realm discovery): the person types an email and
// the sign-in page learns whether that email's domain signs in through an
// organization's SSO (docs/architecture/sso-authentication.md, "Email-first
// sign-in").
//
// What it reveals is domain-level only and only for claimed domains: an SSO
// domain is claimed by one organization after DNS proof, and that
// organization's SSO is the way in for everyone at the domain. Whether the
// email has an account is never part of the answer, and the answer has the
// same shape for every email.

// DomainOwnerLookup answers which organization holds an email domain verified
// for SSO (domainverify.Service.OwnerOfDomain).
type DomainOwnerLookup interface {
	OwnerOfDomain(ctx context.Context, domain string) (shared.ID, bool, error)
}

// SetDomainOwnerLookup wires email-first discovery.
func (s *SSOService) SetDomainOwnerLookup(l DomainOwnerLookup) { s.domainOwner = l }

// Discovery next steps.
const (
	DiscoverNextPassword = "password"
	DiscoverNextSSO      = "sso"
)

// DiscoverResult is the answer to an email: the same fields always.
type DiscoverResult struct {
	// Next is "sso" when the email's domain signs in through an
	// organization's SSO, else "password" (password or social sign-in).
	Next string `json:"next"`
	// Org is the organization slug whose SSO to start ("" for password).
	Org string `json:"org"`
}

// Discover answers where an email signs in. It never fails: any error or
// unknown domain answers "password". The same lookups run whatever the
// email, so the answer's latency does not depend on whether the domain is
// claimed.
func (s *SSOService) Discover(ctx context.Context, email string) DiscoverResult {
	password := DiscoverResult{Next: DiscoverNextPassword}
	domain := ""
	if at := strings.LastIndex(email, "@"); at > 0 && at < len(email)-1 {
		domain = strings.ToLower(strings.TrimSpace(email[at+1:]))
	}
	if s.domainOwner == nil || domain == "" {
		return password
	}
	owner, ok, err := s.domainOwner.OwnerOfDomain(ctx, domain)
	if err != nil {
		s.logger.Warn("sign-in discovery: domain owner lookup failed", "error", err)
		return password
	}
	tenantID := shared.NewID() // matches nothing: keeps the work the same
	if ok {
		tenantID = owner
	}
	t, terr := s.tenantRepo.GetByID(ctx, tenantID)
	if !ok || terr != nil {
		return password
	}
	providers, perr := s.GetProvidersForTenant(ctx, t.Slug())
	if perr != nil || len(providers) == 0 {
		return password
	}
	return DiscoverResult{Next: DiscoverNextSSO, Org: t.Slug()}
}
