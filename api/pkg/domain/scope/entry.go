package scope

// Scope entries: expiry, reason, tier ceiling and widening approvals on a
// scope target (RFC-054 §5, §6.1, owner decisions S3 and S6).
//
// A target authorizes active probes only while it is IN EFFECT: status
// active and not past its expiry. A new entry that needs approvals, a member's
// request and a widened entry are pending until enough distinct approvers,
// none of them the requester, approve.

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Tier is the probe intensity an entry allows at most: T0 passive, T1 safe
// active, T2 intrusive (RFC-036 tiers).
type Tier int

// Tiers.
const (
	TierPassive   Tier = 0
	TierActive    Tier = 1
	TierIntrusive Tier = 2
)

// String is the wire form: t0, t1, t2.
func (t Tier) String() string { return fmt.Sprintf("t%d", int(t)) }

// Valid reports whether t is a known tier.
func (t Tier) Valid() bool { return t >= TierPassive && t <= TierIntrusive }

// ParseTier reads t0, t1 or t2 (case-insensitive).
func ParseTier(s string) (Tier, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "t0":
		return TierPassive, nil
	case "t1":
		return TierActive, nil
	case "t2":
		return TierIntrusive, nil
	}
	return 0, fmt.Errorf("%w: max_tier must be t0, t1 or t2", shared.ErrValidation)
}

// Bounds of an entry (RFC-054 §6.1). One-off entries expire within the
// tenant's one_off_max_days (1..MaxOneOffDays).
const (
	MaxOneOffDays     = 30
	DefaultOneOffDays = 7
	MaxReasonLength   = 1000
	MaxApprovals      = 2
)

// Approval is one approver's approval of a pending entry.
type Approval struct {
	UserID     string
	ApprovedAt time.Time
}

// Entry errors.
var (
	ErrEntryNotPending   = shared.NewDomainError("ENTRY_NOT_PENDING", "the scope entry is not awaiting approval", shared.ErrConflict)
	ErrEntryExpired      = shared.NewDomainError("ENTRY_EXPIRED", "the scope entry expired while waiting for approval; renew it", shared.ErrConflict)
	ErrEntrySelfApproval = shared.NewDomainError("ENTRY_SELF_APPROVAL", "you cannot approve a scope entry you requested or widened", shared.ErrForbidden)
	ErrEntryApprovedOnce = shared.NewDomainError("ENTRY_ALREADY_APPROVED", "you already approved this scope entry", shared.ErrConflict)
	ErrEntryRejected     = shared.NewDomainError("ENTRY_REJECTED", "the scope entry was rejected; create a new one", shared.ErrConflict)
	ErrReasonRequiredFor = shared.NewDomainError("REASON_REQUIRED", "a reason is required for an expiring entry, a request and an intrusive entry", shared.ErrValidation)
	ErrIntrusiveNeeds    = shared.NewDomainError("INTRUSIVE_NEEDS_EXPIRY", "a t2 (intrusive) entry needs an expiry", shared.ErrValidation)
)

// EntryOptions are the entry fields of a new target.
type EntryOptions struct {
	Reason            string
	ExpiresAt         *time.Time
	MaxTier           Tier
	ApprovalsRequired int
	// Now is the clock (zero: time.Now()).
	Now time.Time
}

// NewEntry creates a scope target with its entry fields. With no approvals
// required it is active at once; otherwise it is pending.
func NewEntry(tenantID shared.ID, targetType TargetType, pattern, description, createdBy string, o EntryOptions) (*Target, error) {
	t, err := NewTarget(tenantID, targetType, pattern, description, createdBy)
	if err != nil {
		return nil, err
	}
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}
	reason := strings.TrimSpace(o.Reason)
	switch {
	case len(reason) > MaxReasonLength:
		return nil, fmt.Errorf("%w: reason must be at most %d characters", shared.ErrValidation, MaxReasonLength)
	case !o.MaxTier.Valid():
		return nil, fmt.Errorf("%w: invalid max_tier", shared.ErrValidation)
	case o.ApprovalsRequired < 0 || o.ApprovalsRequired > MaxApprovals:
		return nil, fmt.Errorf("%w: approvals_required must be 0..%d", shared.ErrValidation, MaxApprovals)
	case o.ExpiresAt != nil && !o.ExpiresAt.After(now):
		return nil, fmt.Errorf("%w: expires_at must be in the future", shared.ErrValidation)
	case o.MaxTier == TierIntrusive && o.ExpiresAt == nil:
		return nil, ErrIntrusiveNeeds
	case (o.ExpiresAt != nil || o.MaxTier == TierIntrusive) && reason == "":
		return nil, ErrReasonRequiredFor
	}
	t.reason = reason
	t.expiresAt = o.ExpiresAt
	t.maxTier = o.MaxTier
	t.approvalsRequired = o.ApprovalsRequired
	t.createdAt, t.updatedAt = now, now
	if o.ApprovalsRequired == 0 {
		t.status = StatusActive
		t.approvedAt = &now
	} else {
		// Pending: not approved yet (NewTarget stamps a plain target as
		// approved at creation).
		t.status = StatusPending
		t.approvedAt = nil
	}
	return t, nil
}

// EntryState is the persisted entry part of a target.
type EntryState struct {
	Reason            string
	ExpiresAt         *time.Time
	MaxTier           Tier
	ApprovalsRequired int
	Approvals         []Approval
	ApprovedAt        *time.Time
	RejectedBy        string
	RejectedAt        *time.Time
}

// RestoreEntry sets the entry part of a target read from persistence.
func (t *Target) RestoreEntry(e EntryState) {
	t.reason = e.Reason
	t.expiresAt = e.ExpiresAt
	t.maxTier = e.MaxTier
	t.approvalsRequired = e.ApprovalsRequired
	t.approvals = e.Approvals
	t.approvedAt = e.ApprovedAt
	t.rejectedBy = e.RejectedBy
	t.rejectedAt = e.RejectedAt
}

// Entry getters.
func (t *Target) Reason() string             { return t.reason }
func (t *Target) ExpiresAt() *time.Time      { return t.expiresAt }
func (t *Target) MaxTier() Tier              { return t.maxTier }
func (t *Target) ApprovalsRequired() int     { return t.approvalsRequired }
func (t *Target) Approvals() []Approval      { return t.approvals }
func (t *Target) ApprovedAt() *time.Time     { return t.approvedAt }
func (t *Target) RejectedBy() string         { return t.rejectedBy }
func (t *Target) RejectedAt() *time.Time     { return t.rejectedAt }
func (t *Target) IsPending() bool            { return t.status == StatusPending }
func (t *Target) IsOneOff() bool             { return t.expiresAt != nil }
func (t *Target) ExpiredAt(n time.Time) bool { return t.expiresAt != nil && !t.expiresAt.After(n) }

// InEffect reports whether the target authorizes active probes now: active
// and not past its expiry.
func (t *Target) InEffect(now time.Time) bool {
	return t.status == StatusActive && !t.ExpiredAt(now)
}

// Approve records userID's approval of a pending entry. The requester (the
// creator, or whoever last widened it) cannot approve, and nobody approves
// twice. When the distinct approvals reach ApprovalsRequired the entry is
// active. It reports whether this approval put the entry into effect.
func (t *Target) Approve(userID string, now time.Time) (bool, error) {
	if userID == "" {
		return false, fmt.Errorf("%w: approver is required", shared.ErrValidation)
	}
	switch {
	case t.status == StatusRejected:
		return false, ErrEntryRejected
	case t.status != StatusPending:
		return false, ErrEntryNotPending
	case t.ExpiredAt(now):
		return false, ErrEntryExpired
	case t.createdBy != "" && userID == t.createdBy:
		return false, ErrEntrySelfApproval
	case slices.ContainsFunc(t.approvals, func(a Approval) bool { return a.UserID == userID }):
		return false, ErrEntryApprovedOnce
	}
	t.approvals = append(t.approvals, Approval{UserID: userID, ApprovedAt: now})
	t.updatedAt = now
	if len(t.approvals) < max(1, t.approvalsRequired) {
		return false, nil
	}
	t.status = StatusActive
	t.approvedAt = &now
	return true, nil
}

// Reject declines a pending entry; it never takes effect.
func (t *Target) Reject(userID string, now time.Time) error {
	if userID == "" {
		return fmt.Errorf("%w: reviewer is required", shared.ErrValidation)
	}
	if t.status != StatusPending {
		return ErrEntryNotPending
	}
	t.status = StatusRejected
	t.rejectedBy = userID
	t.rejectedAt = &now
	t.updatedAt = now
	return nil
}

// Widen puts the entry back to review after a widening change by requester
// (a later or removed expiry, a higher tier, an activation): with approvals
// required it is pending with no approvals and requester becomes the one who
// cannot approve; with none it is active at once.
func (t *Target) Widen(requester string, approvalsRequired int, now time.Time) {
	t.approvals = nil
	t.approvalsRequired = approvalsRequired
	t.rejectedBy, t.rejectedAt = "", nil
	if requester != "" {
		t.createdBy = requester
	}
	t.updatedAt = now
	if approvalsRequired == 0 {
		t.status = StatusActive
		t.approvedAt = &now
		return
	}
	t.status = StatusPending
	t.approvedAt = nil
}

// SetExpiry changes the expiry (nil: permanent).
func (t *Target) SetExpiry(at *time.Time, now time.Time) {
	t.expiresAt = at
	t.updatedAt = now
}

// SetMaxTier changes the tier ceiling.
func (t *Target) SetMaxTier(tier Tier, now time.Time) {
	t.maxTier = tier
	t.updatedAt = now
}

// SetReason changes the reason.
func (t *Target) SetReason(reason string, now time.Time) error {
	reason = strings.TrimSpace(reason)
	if len(reason) > MaxReasonLength {
		return fmt.Errorf("%w: reason must be at most %d characters", shared.ErrValidation, MaxReasonLength)
	}
	t.reason = reason
	t.updatedAt = now
	return nil
}

// MarkExpired records that the entry's expiry passed.
func (t *Target) MarkExpired(now time.Time) {
	t.status = StatusExpired
	t.updatedAt = now
}

// ExtendsExpiry reports whether next ends later than the current expiry
// (nil = never ends).
func (t *Target) ExtendsExpiry(next *time.Time) bool {
	return extendsWindow(t.expiresAt, next)
}

// Covers is the wire description of what a pattern covers: name,
// domain_and_subdomains, addresses or pattern.
func (t *Target) Covers() string {
	switch t.targetType {
	case TargetTypeDomain, TargetTypeSubdomain, TargetTypeEmailDomain:
		if w, _ := splitDomainWildcard(t.pattern); w {
			return "domain_and_subdomains"
		}
		return "name"
	case TargetTypeIPAddress, TargetTypeIPRange, TargetTypeCIDR:
		return "addresses"
	}
	return "pattern"
}
