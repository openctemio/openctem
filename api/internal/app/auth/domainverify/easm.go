package domainverify

// Tenant self-service domain verification for EASM (research/22 P0-10,
// owner decision E6; architecture: docs/architecture/easm.md).
//
// A tenant member with scope:write proves control of a domain with the same
// DNS TXT record as the admin flow. The row gets purpose "easm": it
// strengthens attribution (names under it auto-confirm through
// fqdn_under_verified_root) and is re-checked every 12 hours like any
// verified domain, but it never admits SSO JIT or SCIM users. Rows set up
// by a platform administrator (purpose "sso") are listed read-only.

import (
	"context"
	"errors"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
)

// ErrVerifyRateLimited is returned when a tenant has run too many
// verification checks in the current window.
var ErrVerifyRateLimited = errors.New("too many verification checks; try again later")

// MaxEASMVerifyPerHour bounds a tenant's verification checks (each one is a
// DNS lookup the platform makes on its behalf).
const MaxEASMVerifyPerHour = 10

// MaxEASMDomainsPerTenant bounds how many domains a tenant may add itself.
const MaxEASMDomainsPerTenant = 200

// ErrTooManyDomains is returned when the tenant has reached the cap.
var ErrTooManyDomains = errors.New("domain limit reached for this organization")

// VerifyLimiter admits one verification check for a tenant.
type VerifyLimiter interface {
	Allow(ctx context.Context, tenantID shared.ID) (bool, error)
}

// SetVerifyLimiter sets the tenant verification limiter. Without one, an
// in-process limiter of MaxEASMVerifyPerHour per tenant is used.
func (s *Service) SetVerifyLimiter(l VerifyLimiter) { s.limiter = l }

func (s *Service) verifyLimiter() VerifyLimiter {
	s.limiterOnce.Do(func() {
		if s.limiter == nil {
			s.limiter = NewWindowLimiter(MaxEASMVerifyPerHour, time.Hour)
		}
	})
	return s.limiter
}

// AddEASMDomain adds a domain the tenant will verify for EASM. A public
// suffix, a shared consumer domain, or a domain the tenant already has
// (either purpose) is refused. Another tenant's row for the same domain is
// irrelevant: rows are per tenant, so nothing reveals it.
func (s *Service) AddEASMDomain(ctx context.Context, tenantID shared.ID, rawDomain string) (*verifieddomain.VerifiedDomain, TXTRecord, error) {
	domain, err := verifieddomain.NormalizeDomain(rawDomain)
	if err != nil {
		return nil, TXTRecord{}, err
	}
	if ps, _ := publicsuffix.PublicSuffix(domain); ps == domain {
		return nil, TXTRecord{}, verifieddomain.ErrInvalidDomain
	}
	if isBlocked(domain) {
		return nil, TXTRecord{}, verifieddomain.ErrBlockedDomain
	}
	existing, err := s.repo.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, TXTRecord{}, err
	}
	if len(existing) >= MaxEASMDomainsPerTenant {
		return nil, TXTRecord{}, ErrTooManyDomains
	}
	token, err := generateToken()
	if err != nil {
		return nil, TXTRecord{}, err
	}
	vd, err := verifieddomain.New(shared.NewID(), tenantID, domain, token)
	if err != nil {
		return nil, TXTRecord{}, err
	}
	vd.WithPurpose(verifieddomain.PurposeEASM)
	if err := s.repo.Create(ctx, vd); err != nil {
		return nil, TXTRecord{}, err
	}
	return vd, Instructions(vd.Domain(), vd.VerificationToken()), nil
}

// easmRow loads a tenant's EASM-purpose row; an SSO row (or another
// tenant's) is not found, so a tenant cannot re-check or delete what an
// administrator set up.
func (s *Service) easmRow(ctx context.Context, tenantID, id shared.ID) (*verifieddomain.VerifiedDomain, error) {
	vd, err := s.repo.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if vd.Purpose() != verifieddomain.PurposeEASM {
		return nil, verifieddomain.ErrNotFound
	}
	return vd, nil
}

// VerifyEASM checks the TXT record of the tenant's EASM-purpose row now,
// within the tenant's hourly budget.
func (s *Service) VerifyEASM(ctx context.Context, tenantID, id shared.ID) (*verifieddomain.VerifiedDomain, error) {
	vd, err := s.easmRow(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	ok, err := s.verifyLimiter().Allow(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrVerifyRateLimited
	}
	s.checkAndStamp(ctx, vd, true)
	if err := s.repo.Update(ctx, vd); err != nil {
		return nil, err
	}
	return vd, nil
}

// DeleteEASM removes the tenant's EASM-purpose row.
func (s *Service) DeleteEASM(ctx context.Context, tenantID, id shared.ID) (*verifieddomain.VerifiedDomain, error) {
	vd, err := s.easmRow(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if err := s.repo.Delete(ctx, tenantID, id); err != nil {
		return nil, err
	}
	return vd, nil
}

// WindowLimiter is an in-process fixed-window limiter per tenant.
type WindowLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	seen   map[shared.ID][]time.Time
	now    func() time.Time
}

// NewWindowLimiter allows limit checks per tenant per window.
func NewWindowLimiter(limit int, window time.Duration) *WindowLimiter {
	return &WindowLimiter{limit: limit, window: window, seen: map[shared.ID][]time.Time{}, now: time.Now}
}

// Allow implements VerifyLimiter (a sliding window over the last checks).
func (l *WindowLimiter) Allow(_ context.Context, tenantID shared.ID) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	cut := now.Add(-l.window)
	kept := l.seen[tenantID][:0]
	for _, t := range l.seen[tenantID] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.limit {
		l.seen[tenantID] = kept
		return false, nil
	}
	l.seen[tenantID] = append(kept, now)
	return true, nil
}
