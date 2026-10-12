// Package domainverify implements DNS-TXT domain-ownership verification and the
// verified-domain gate for SSO JIT auto-provisioning (SSO P1).
//
// An IdP proves WHO a user is; a DNS-proven domain proves a tenant may CLAIM
// that domain's users. A tenant admin adds a domain, publishes the returned TXT
// record, and the service confirms it — only then may that domain's users be
// auto-joined. All state transitions are fail-closed: a domain is verified ONLY
// when the exact token is observed, and a verified domain whose record later
// disappears is downgraded to failed.
package domainverify

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
	"github.com/openctemio/openctem/api/pkg/emaildomain"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	// txtHostPrefix is prepended to the domain to form the TXT record host.
	txtHostPrefix = "_openctem-verify"
	// txtValuePrefix is the fixed prefix of the TXT record value; the token follows.
	txtValuePrefix = "openctem-domain-verification="
	// tokenBytes is the entropy of the verification token (32 bytes → 43 b64 chars).
	tokenBytes = 32
)

// Resolver looks up DNS TXT records. The real implementation wraps
// net.Resolver; tests inject a mock so verification is deterministic.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// NetResolver is the production Resolver backed by the system DNS resolver.
type NetResolver struct {
	r *net.Resolver
}

// NewNetResolver returns a Resolver using Go's default net.Resolver.
func NewNetResolver() *NetResolver {
	return &NetResolver{r: net.DefaultResolver}
}

// LookupTXT resolves TXT records for name.
func (n *NetResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return n.r.LookupTXT(ctx, name)
}

// Service manages verified domains and answers the JIT gate query.
type Service struct {
	repo     verifieddomain.Repository
	resolver Resolver
	logger   *logger.Logger

	limiter     VerifyLimiter
	limiterOnce sync.Once

	// claimListener hears SSO claim transitions (RFC-058 home cascade).
	claimListener ClaimListener
}

// NewService creates a Service. When resolver is nil a NetResolver is used.
func NewService(repo verifieddomain.Repository, resolver Resolver, log *logger.Logger) *Service {
	if resolver == nil {
		resolver = NewNetResolver()
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{repo: repo, resolver: resolver, logger: log.With("service", "domainverify")}
}

// TXTRecord describes the DNS record a tenant must publish to prove ownership.
type TXTRecord struct {
	Host  string `json:"host"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Instructions returns the TXT record to publish for domain+token. It does not
// touch persistence, so handlers can render instructions for a stored row.
func Instructions(domain, token string) TXTRecord {
	return TXTRecord{
		Host:  txtHostPrefix + "." + domain,
		Type:  "TXT",
		Value: txtValuePrefix + token,
	}
}

// expectedTXTValue is the exact TXT value that proves ownership for a token.
func expectedTXTValue(token string) string {
	return txtValuePrefix + token
}

// isBlocked reports whether no single organization can own a normalized
// domain: a public suffix or a name under a shared platform suffix
// (github.io), a free consumer mailbox provider, or a disposable-address
// service. Allowing one would let an organization auto-join every user of it.
func isBlocked(domain string) bool {
	return emaildomain.ClaimRefusal(domain) != emaildomain.ReasonNone
}

// claimRefusal enforces that an SSO domain is claimed by one organization,
// platform-wide. It returns ErrDomainClaimed when another organization holds
// the domain verified for SSO, or lost its DNS proof less than
// ClaimDisputeWindow ago (the holder may restore its record and keep the
// claim). EASM rows never count: EASM proof admits nobody and is not
// exclusive. The other organization is never named to the caller.
func (s *Service) claimRefusal(ctx context.Context, vd *verifieddomain.VerifiedDomain, now time.Time) error {
	claims, err := s.repo.ListSSOClaims(ctx, vd.Domain())
	if err != nil {
		return err
	}
	for _, c := range claims {
		if c.TenantID().Equals(vd.TenantID()) || c.Purpose() != verifieddomain.PurposeSSO {
			continue
		}
		if c.IsVerified() {
			return verifieddomain.ErrDomainClaimed
		}
		if l := c.LapsedAt(); l != nil && now.Sub(*l) < verifieddomain.ClaimDisputeWindow {
			return verifieddomain.ErrDomainClaimed
		}
	}
	return nil
}

// generateToken returns a random URL-safe verification token.
func generateToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// AddDomain normalizes and validates a domain, rejects shared/public domains,
// generates a token, and stores a pending row. Returns the row and the TXT
// record the tenant must publish.
func (s *Service) AddDomain(ctx context.Context, tenantID shared.ID, rawDomain string) (*verifieddomain.VerifiedDomain, TXTRecord, error) {
	domain, err := verifieddomain.NormalizeDomain(rawDomain)
	if err != nil {
		return nil, TXTRecord{}, err
	}
	if isBlocked(domain) {
		return nil, TXTRecord{}, verifieddomain.ErrBlockedDomain
	}

	token, err := generateToken()
	if err != nil {
		return nil, TXTRecord{}, fmt.Errorf("generate token: %w", err)
	}

	vd, err := verifieddomain.New(shared.NewID(), tenantID, domain, token)
	if err != nil {
		return nil, TXTRecord{}, err
	}
	if err := s.repo.Create(ctx, vd); err != nil {
		if !errors.Is(err, verifieddomain.ErrAlreadyExists) {
			return nil, TXTRecord{}, err
		}
		// The tenant verified it for EASM itself: the administrator makes it
		// an SSO domain, keeping its token and verification (E6).
		existing, gerr := s.repo.GetByTenantAndDomain(ctx, tenantID, domain)
		if gerr != nil || existing.Purpose() != verifieddomain.PurposeEASM {
			return nil, TXTRecord{}, err
		}
		// A verified EASM row becomes a verified SSO claim at once, so it
		// passes the same exclusivity check as a fresh verification.
		if existing.IsVerified() {
			if cerr := s.claimRefusal(ctx, existing, time.Now().UTC()); cerr != nil {
				return nil, TXTRecord{}, cerr
			}
		}
		existing.PromoteToSSO(time.Now())
		if uerr := s.repo.Update(ctx, existing); uerr != nil {
			return nil, TXTRecord{}, uerr
		}
		vd = existing
	}
	return vd, Instructions(vd.Domain(), vd.VerificationToken()), nil
}

// List returns all verified-domain rows for a tenant.
func (s *Service) List(ctx context.Context, tenantID shared.ID) ([]*verifieddomain.VerifiedDomain, error) {
	return s.repo.ListByTenant(ctx, tenantID)
}

// Delete removes a tenant's verified-domain row by id.
func (s *Service) Delete(ctx context.Context, tenantID, id shared.ID) error {
	vd, err := s.repo.GetByID(ctx, tenantID, id)
	if err != nil {
		return err
	}
	wasHolder := vd.IsVerified() && !vd.ClaimConflict()
	if err := s.repo.Delete(ctx, tenantID, id); err != nil {
		return err
	}
	if wasHolder && s.claimListener != nil && vd.Purpose() == verifieddomain.PurposeSSO {
		s.claimListener.HomeDomainLost(ctx, vd.TenantID(), vd.Domain())
	}
	return nil
}

// VerifyByID runs verification for a stored row (admin "verify now"). It loads
// the row (tenant-scoped), performs the DNS check, persists the outcome, and
// returns the updated row.
func (s *Service) VerifyByID(ctx context.Context, tenantID, id shared.ID) (*verifieddomain.VerifiedDomain, error) {
	vd, err := s.repo.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	// Only a row that is not verified yet can take a claim; a verified one
	// is simply re-checked (it already holds the claim).
	if vd.Purpose() == verifieddomain.PurposeSSO && !vd.IsVerified() {
		if err := s.claimRefusal(ctx, vd, time.Now().UTC()); err != nil {
			s.logger.Info("SSO domain verification refused: claimed by another organization",
				"tenant_id", tenantID.String(), "domain", vd.Domain())
			return nil, err
		}
	}
	wasHolder := vd.IsVerified() && !vd.ClaimConflict()
	s.checkAndStamp(ctx, vd, true)
	if err := s.repo.Update(ctx, vd); err != nil {
		return nil, err
	}
	s.claimChanged(ctx, vd, wasHolder)
	return vd, nil
}

// checkAndStamp performs the DNS TXT lookup for vd and mutates its status.
// promote controls whether a successful match may set the row verified (true
// for pending/verify-now); re-verify passes promote=true too since a verified
// row that still resolves simply re-stamps verified. Fail-closed: a lookup
// error or a missing token never verifies, and a verified row that no longer
// resolves is downgraded to failed via MarkChecked.
func (s *Service) checkAndStamp(ctx context.Context, vd *verifieddomain.VerifiedDomain, promote bool) {
	now := time.Now().UTC()
	host := txtHostPrefix + "." + vd.Domain()
	records, err := s.resolver.LookupTXT(ctx, host)
	if err != nil {
		s.logger.Debug("TXT lookup failed", "domain", vd.Domain(), "error", err)
		vd.MarkChecked(now) // fail-closed; downgrades a lapsed verified row
		return
	}

	want := expectedTXTValue(vd.VerificationToken())
	for _, rec := range records {
		if strings.TrimSpace(rec) == want {
			if promote {
				vd.MarkVerified(now)
			} else {
				vd.MarkChecked(now)
			}
			return
		}
	}
	// Token not present: pending stays pending, verified downgrades to failed.
	vd.MarkChecked(now)
}

// IsVerifiedDomain reports whether emailDomain is a verified domain for the
// tenant. Tenant-scoped and fail-closed: normalization failure, a missing row,
// or a non-verified status all return false. A lookup error is surfaced so the
// caller can also fail closed.
func (s *Service) IsVerifiedDomain(ctx context.Context, tenantID, emailDomain string) (bool, error) {
	// A malformed tenant id or email domain is not an operational error — it
	// simply cannot match a verified row, so fail closed (not verified, no error).
	tid, terr := shared.IDFromString(tenantID)
	if terr != nil {
		return false, nil //nolint:nilerr // malformed input ⇒ fail-closed, not an error
	}
	domain, derr := verifieddomain.NormalizeDomain(emailDomain)
	if derr != nil {
		return false, nil //nolint:nilerr // malformed input ⇒ fail-closed, not an error
	}
	vd, err := s.repo.GetByTenantAndDomain(ctx, tid, domain)
	if err != nil {
		if shared.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	// Only an SSO-purpose domain admits users; a domain the tenant verified
	// for EASM never does (research/22 E6).
	return vd.AdmitsSSO(), nil
}

// settleClaimConflict clears a pre-exclusivity conflict flag once the row is
// the only verified SSO claim left for its domain (the platform administrator
// removed the others, or their proof lapsed).
func (s *Service) settleClaimConflict(ctx context.Context, vd *verifieddomain.VerifiedDomain) {
	if !vd.ClaimConflict() || !vd.IsVerified() {
		return
	}
	claims, err := s.repo.ListSSOClaims(ctx, vd.Domain())
	if err != nil {
		return
	}
	for _, c := range claims {
		if !c.ID().Equals(vd.ID()) && c.IsVerified() {
			return
		}
	}
	vd.ClearClaimConflict(time.Now())
	s.logger.Info("SSO domain claim conflict settled", "tenant_id", vd.TenantID().String(), "domain", vd.Domain())
}

// ReverifyDue re-checks verified domains that have not been checked since
// `staleness` ago. A domain whose TXT record vanished is downgraded to failed
// (fail-closed) so a lapsed/hijacked domain loses JIT authority. Returns the
// number of rows whose status changed.
// ClaimListener hears when an organization stops or starts holding an SSO
// domain (RFC-058: external members homed by that domain are suspended, then
// restored).
type ClaimListener interface {
	HomeDomainLost(ctx context.Context, home shared.ID, domain string)
	HomeDomainRestored(ctx context.Context, home shared.ID, domain string)
}

// SetClaimListener wires the claim transitions.
func (s *Service) SetClaimListener(l ClaimListener) { s.claimListener = l }

// claimChanged tells the listener when vd's SSO claim changed from before.
func (s *Service) claimChanged(ctx context.Context, vd *verifieddomain.VerifiedDomain, wasHolder bool) {
	if s.claimListener == nil || vd.Purpose() != verifieddomain.PurposeSSO {
		return
	}
	isHolder := vd.IsVerified() && !vd.ClaimConflict()
	switch {
	case wasHolder && !isHolder:
		s.claimListener.HomeDomainLost(ctx, vd.TenantID(), vd.Domain())
	case !wasHolder && isHolder:
		s.claimListener.HomeDomainRestored(ctx, vd.TenantID(), vd.Domain())
	}
}

func (s *Service) ReverifyDue(ctx context.Context, staleness time.Duration, batch int) (int, error) {
	if batch <= 0 {
		batch = 100
	}
	cutoff := time.Now().UTC().Add(-staleness)
	due, err := s.repo.ListDueForRecheck(ctx, cutoff, batch)
	if err != nil {
		return 0, err
	}
	changed := 0
	for _, vd := range due {
		before := vd.Status()
		wasHolder := vd.IsVerified() && !vd.ClaimConflict()
		s.checkAndStamp(ctx, vd, true)
		s.settleClaimConflict(ctx, vd)
		if uerr := s.repo.Update(ctx, vd); uerr != nil {
			s.logger.Warn("re-verify update failed", "domain", vd.Domain(), "error", uerr)
			continue
		}
		s.claimChanged(ctx, vd, wasHolder)
		if vd.Status() != before {
			changed++
			s.logger.Info("verified domain status changed on re-verify",
				"tenant_id", vd.TenantID().String(), "domain", vd.Domain(),
				"from", string(before), "to", string(vd.Status()))
		}
	}
	return changed, nil
}
