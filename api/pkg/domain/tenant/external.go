package tenant

import (
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// External members (docs/rfcs/RFC-058-external-members.md): people who belong
// to an organization that does not own their email domain.

// MemberKind says whether the organization manages the member's address.
type MemberKind string

const (
	// MemberKindInternal is the default: the organization owns the member's
	// email domain, or the member joined before external members existed.
	MemberKindInternal MemberKind = "internal"
	// MemberKindExternal is a member whose email domain the organization does
	// not own: another organization's staff (home organization set), or an
	// address no organization manages (a personal or an unclaimed work domain).
	MemberKindExternal MemberKind = "external"
)

// IsValid reports whether k is a known kind.
func (k MemberKind) IsValid() bool { return k == MemberKindInternal || k == MemberKindExternal }

// Expiry limits for unmanaged external members (no organization manages the
// address, so expiry is what ends their access).
const (
	DefaultExternalAccessDays = 90
	MaxExternalAccessDays     = 365
	maxExpiryReasonLen        = 500
)

// SuspendedReasonExpired marks a membership suspended because its access
// expired.
const SuspendedReasonExpired = "expired"

// SuspendedReasonTrustRevoked marks an external membership suspended because
// the trust between the host and the member's home organization ended.
const SuspendedReasonTrustRevoked = "trust_revoked"

// SuspendExternal suspends an active external membership for a system reason
// (no human suspender).
func (m *Membership) SuspendExternal(reason string) error {
	if !m.IsExternal() {
		return fmt.Errorf("%w: membership is not external", shared.ErrValidation)
	}
	if !m.IsActive() {
		return fmt.Errorf("%w: membership is not active", shared.ErrValidation)
	}
	if err := m.Suspend(shared.ID{}); err != nil {
		return err
	}
	m.suspendedReason = reason
	return nil
}

// Classification is how an address relates to an organization, decided from
// the platform-wide verified SSO domains.
type Classification struct {
	Kind MemberKind
	// HomeTenantID is the organization holding the address's verified SSO
	// domain; nil when none does.
	HomeTenantID *shared.ID
	// Domain is the address's email domain (lower case).
	Domain string
	// Personal is set for consumer mail domains (gmail.com, outlook.com, ...).
	Personal bool
}

// Managed reports whether an organization manages the address (it has a home
// organization), so its lifecycle follows that organization.
func (c Classification) Managed() bool { return c.HomeTenantID != nil }

// ExpiryRequired reports whether the membership must expire: an external
// member that no organization manages.
func (c Classification) ExpiryRequired() bool { return c.Kind == MemberKindExternal && !c.Managed() }

// ExternalAccess is the access an external member is given.
type ExternalAccess struct {
	ExpiresAt *time.Time
	Reason    string
}

// Validate checks the expiry against the classification at time now.
func (a ExternalAccess) Validate(c Classification, now time.Time) error {
	if len(a.Reason) > maxExpiryReasonLen {
		return fmt.Errorf("%w: the access reason is longer than %d characters", shared.ErrValidation, maxExpiryReasonLen)
	}
	if a.ExpiresAt == nil {
		if c.ExpiryRequired() {
			return fmt.Errorf("%w: access for someone outside any organization must expire (at most %d days)", shared.ErrValidation, MaxExternalAccessDays)
		}
		return nil
	}
	if !a.ExpiresAt.After(now) {
		return fmt.Errorf("%w: the access expiry must be in the future", shared.ErrValidation)
	}
	if a.ExpiresAt.After(now.Add(MaxExternalAccessDays * 24 * time.Hour)) {
		return fmt.Errorf("%w: access may be granted for at most %d days", shared.ErrValidation, MaxExternalAccessDays)
	}
	return nil
}

// Kind returns the member kind (internal unless set).
func (m *Membership) Kind() MemberKind {
	if m.kind == "" {
		return MemberKindInternal
	}
	return m.kind
}

// IsExternal reports whether the member is external.
func (m *Membership) IsExternal() bool { return m.Kind() == MemberKindExternal }

// HomeTenantID returns the external member's home organization, or nil.
func (m *Membership) HomeTenantID() *shared.ID { return m.homeTenantID }

// HomeDomain returns the email domain recorded at classification.
func (m *Membership) HomeDomain() string { return m.homeDomain }

// ExpiresAt returns when the membership is suspended automatically, or nil.
func (m *Membership) ExpiresAt() *time.Time { return m.expiresAt }

// ExpiryReason returns why the access was given until ExpiresAt.
func (m *Membership) ExpiryReason() string { return m.expiryReason }

// SuspendedReason returns why the membership was suspended (e.g. expired).
func (m *Membership) SuspendedReason() string { return m.suspendedReason }

// Classify records how the member's address relates to the organization and
// the access an external member is given. An owner is never external.
func (m *Membership) Classify(c Classification, access ExternalAccess, now time.Time) error {
	if !c.Kind.IsValid() {
		return fmt.Errorf("%w: invalid member kind", shared.ErrValidation)
	}
	if c.Kind == MemberKindExternal {
		if m.role == RoleOwner {
			return fmt.Errorf("%w: someone outside the organization cannot be an owner", shared.ErrValidation)
		}
		if err := access.Validate(c, now); err != nil {
			return err
		}
	}
	m.kind = c.Kind
	m.homeDomain = strings.ToLower(c.Domain)
	m.homeTenantID = nil
	if c.Kind == MemberKindExternal {
		m.homeTenantID = c.HomeTenantID
	}
	m.expiresAt = access.ExpiresAt
	m.expiryReason = strings.TrimSpace(access.Reason)
	return nil
}

// IsExpired reports whether the access has expired at now.
func (m *Membership) IsExpired(now time.Time) bool {
	return m.expiresAt != nil && !m.expiresAt.After(now)
}

// SuspendExpired suspends an active membership whose access expired.
func (m *Membership) SuspendExpired(now time.Time) error {
	if !m.IsActive() {
		return fmt.Errorf("%w: membership is not active", shared.ErrValidation)
	}
	if !m.IsExpired(now) {
		return fmt.Errorf("%w: membership has not expired", shared.ErrValidation)
	}
	if err := m.Suspend(shared.ID{}); err != nil {
		return err
	}
	m.suspendedReason = SuspendedReasonExpired
	return nil
}

// WithAccessState restores the external-member fields from persistence.
func (m *Membership) WithAccessState(kind MemberKind, home *shared.ID, domain string,
	expiresAt *time.Time, expiryReason, suspendedReason string) *Membership {
	m.kind = kind
	m.homeTenantID = home
	m.homeDomain = domain
	m.expiresAt = expiresAt
	m.expiryReason = expiryReason
	m.suspendedReason = suspendedReason
	return m
}
