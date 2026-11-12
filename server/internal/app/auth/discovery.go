package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"time"

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
	// Org is an opaque, expiring reference to the organization whose SSO to
	// start ("" for password). It is accepted wherever an organization slug
	// is (the providers list and the authorize start), so discovery never
	// hands out an organization's slug.
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
	ref := s.orgRef(t.ID())
	if ref == "" {
		return password
	}
	return DiscoverResult{Next: DiscoverNextSSO, Org: ref}
}

// orgRefPrefix marks an opaque organization reference (never a valid slug:
// slugs have no dots).
const orgRefPrefix = "r1."

// orgRefTTL bounds how long a discovery reference starts an SSO sign-in.
const orgRefTTL = 30 * time.Minute

// SetDiscoveryKey sets the key that signs discovery references. Without it,
// discovery answers "password" (no reference can be made).
func (s *SSOService) SetDiscoveryKey(key []byte) { s.discoveryKey = key }

// orgRef signs an organization id and an expiry.
func (s *SSOService) orgRef(tenantID shared.ID) string {
	if len(s.discoveryKey) == 0 {
		return ""
	}
	payload := tenantID.String() + "|" + strconv.FormatInt(time.Now().Add(orgRefTTL).Unix(), 10)
	return orgRefPrefix + base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(s.orgRefMAC(payload))
}

func (s *SSOService) orgRefMAC(payload string) []byte {
	h := hmac.New(sha256.New, s.discoveryKey)
	h.Write([]byte("sso-discovery/v1|" + payload))
	return h.Sum(nil)
}

// ResolveOrg turns an organization reference from discovery into the
// organization's slug. Anything else is returned unchanged (a slug typed or
// linked by an organization). An invalid or expired reference resolves to ""
// and so matches no organization.
func (s *SSOService) ResolveOrg(ctx context.Context, org string) string {
	if !strings.HasPrefix(org, orgRefPrefix) {
		return org
	}
	p, m, ok := strings.Cut(strings.TrimPrefix(org, orgRefPrefix), ".")
	if !ok || len(s.discoveryKey) == 0 {
		return ""
	}
	payload, err1 := base64.RawURLEncoding.DecodeString(p)
	mac, err2 := base64.RawURLEncoding.DecodeString(m)
	if err1 != nil || err2 != nil || !hmac.Equal(mac, s.orgRefMAC(string(payload))) {
		return ""
	}
	id, expStr, ok := strings.Cut(string(payload), "|")
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if !ok || err != nil || time.Now().Unix() > exp {
		return ""
	}
	tid, err := shared.IDFromString(id)
	if err != nil {
		return ""
	}
	t, err := s.tenantRepo.GetByID(ctx, tid)
	if err != nil {
		return ""
	}
	return t.Slug()
}
