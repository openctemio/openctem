package tenant

import (
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Who may add one-off (expiring) scope entries (RFC-054 §6.3).
const (
	OneOffAdmins            = "admins"
	OneOffAdminsAndRequests = "admins_and_requests"
	OneOffDisabled          = "disabled"
)

// Scope settings bounds.
const (
	MaxScopeOneOffDays     = 30
	DefaultScopeOneOffDays = 7
	MaxScopeApprovals      = 2
)

// The longest an intrusive (t2) scope entry may last (RFC-054 §12.4): an
// owner-only setting. Permanent t2 entries are re-attested.
const (
	T2Max7Days       = "7d"
	T2Max30Days      = "30d"
	T2Max90Days      = "90d"
	T2Max365Days     = "365d"
	T2MaxPermanent   = "permanent"
	DefaultT2MaxDays = T2Max30Days
	// MaxT2ExpiryDays bounds expires_in_days of a t2 entry when permanent
	// t2 entries are allowed.
	MaxT2ExpiryDays = 365
)

var t2MaxDays = map[string]int{T2Max7Days: 7, T2Max30Days: 30, T2Max90Days: 90, T2Max365Days: 365}

// ScopeSettings are the organization's scope knobs (RFC-054 §6.3, owner
// decision S5). They adjust friction inside the authorized set; none of them
// turns scope off, and the platform guardrails are not here. The zero value
// is the default: auto-join on, admins and member requests, 7 days, the
// default approval count, t1.
type ScopeSettings struct {
	// AutoJoinDisabled stops confirming discovered names a scope entry covers
	// (they go to the review queue instead).
	AutoJoinDisabled bool `json:"auto_join_disabled,omitempty"`
	// OneOffTargets: admins, admins_and_requests (default) or disabled.
	OneOffTargets string `json:"one_off_targets,omitempty"`
	// OneOffMaxDays bounds an expiring entry, 1..30 (0: 7).
	OneOffMaxDays int `json:"one_off_max_days,omitempty"`
	// WideningApprovals is 0, 1 or 2 approvals for a widening; nil is the
	// default min(1, admins-1).
	WideningApprovals *int `json:"widening_approvals,omitempty"`
	// DefaultMaxTier is t0 or t1 ("" = t1). t2 is never a default.
	DefaultMaxTier string `json:"default_max_tier,omitempty"`

	// Owner-only fields (IntrusiveScopeSettings): PUT /scope/settings keeps
	// them; only PUT /scope/settings/intrusive changes them.

	// T2MaxDuration is the longest a t2 entry may last: 7d, 30d, 90d, 365d
	// or permanent ("" = 30d).
	T2MaxDuration string `json:"t2_max_duration,omitempty"`
}

// IntrusiveScopeSettings are the owner-only scope settings (RFC-054 §12.4).
type IntrusiveScopeSettings struct {
	T2MaxDuration string
}

// WithIntrusive returns s with the owner-only fields of i.
func (s ScopeSettings) WithIntrusive(i IntrusiveScopeSettings) ScopeSettings {
	s.T2MaxDuration = i.T2MaxDuration
	return s
}

// Intrusive returns the owner-only fields of s.
func (s ScopeSettings) Intrusive() IntrusiveScopeSettings {
	return IntrusiveScopeSettings{T2MaxDuration: s.T2MaxDuration}
}

// T2Max returns the t2 duration bound with its default: the days, or
// permanent (then days is MaxT2ExpiryDays, the bound of an expiring t2 entry).
func (s ScopeSettings) T2Max() (days int, permanent bool) {
	if s.T2MaxDuration == T2MaxPermanent {
		return MaxT2ExpiryDays, true
	}
	if d, ok := t2MaxDays[s.T2MaxDuration]; ok {
		return d, false
	}
	return t2MaxDays[DefaultT2MaxDays], false
}

// T2Duration returns the t2 duration setting with its default.
func (s ScopeSettings) T2Duration() string {
	if s.T2MaxDuration == "" {
		return DefaultT2MaxDays
	}
	return s.T2MaxDuration
}

// Validate checks the bounds.
func (s ScopeSettings) Validate() error {
	switch s.OneOffTargets {
	case "", OneOffAdmins, OneOffAdminsAndRequests, OneOffDisabled:
	default:
		return fmt.Errorf("%w: one_off_targets must be admins, admins_and_requests or disabled", shared.ErrValidation)
	}
	if s.OneOffMaxDays < 0 || s.OneOffMaxDays > MaxScopeOneOffDays {
		return fmt.Errorf("%w: one_off_max_days must be between 1 and %d", shared.ErrValidation, MaxScopeOneOffDays)
	}
	if s.WideningApprovals != nil && (*s.WideningApprovals < 0 || *s.WideningApprovals > MaxScopeApprovals) {
		return fmt.Errorf("%w: widening_approvals must be 0, 1 or 2", shared.ErrValidation)
	}
	switch s.DefaultMaxTier {
	case "", "t0", "t1":
	default:
		return fmt.Errorf("%w: default_max_tier must be t0 or t1", shared.ErrValidation)
	}
	if _, ok := t2MaxDays[s.T2MaxDuration]; !ok && s.T2MaxDuration != "" && s.T2MaxDuration != T2MaxPermanent {
		return fmt.Errorf("%w: t2_max_duration must be 7d, 30d, 90d, 365d or permanent", shared.ErrValidation)
	}
	return nil
}

// OneOffPolicy returns the one-off policy with its default.
func (s ScopeSettings) OneOffPolicy() string {
	if s.OneOffTargets == "" {
		return OneOffAdminsAndRequests
	}
	return s.OneOffTargets
}

// MaxDays returns the one-off bound with its default.
func (s ScopeSettings) MaxDays() int {
	if s.OneOffMaxDays <= 0 {
		return DefaultScopeOneOffDays
	}
	return s.OneOffMaxDays
}

// DefaultDays is the duration of a one-off entry with no explicit expiry:
// 7 days, or less when the bound is lower.
func (s ScopeSettings) DefaultDays() int {
	return min(DefaultScopeOneOffDays, s.MaxDays())
}

// Tier returns the default tier with its default (t1).
func (s ScopeSettings) Tier() string {
	if s.DefaultMaxTier == "" {
		return "t1"
	}
	return s.DefaultMaxTier
}

// EffectiveApprovals is how many approvers (other than the requester) a
// widening needs in an organization with admins administrators (RFC-054 §7,
// owner decision S3):
//
//   - unset: min(1, admins-1), so a one-admin organization is not deadlocked;
//   - a set value is capped at admins-1, so the administrators other than
//     the requester can always satisfy it;
//   - an organization with two or more admins never goes below 1;
//   - intrusive (t2) never goes below 1.
func (s ScopeSettings) EffectiveApprovals(admins int, intrusive bool) int {
	n := min(1, max(0, admins-1))
	if s.WideningApprovals != nil {
		n = min(*s.WideningApprovals, max(0, admins-1))
	}
	if admins >= 2 && n < 1 {
		n = 1
	}
	if intrusive && n < 1 {
		n = 1
	}
	return min(n, MaxScopeApprovals)
}

// UpdateScopeSettings replaces the organization's scope settings.
func (t *Tenant) UpdateScopeSettings(s ScopeSettings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	settings := t.TypedSettings()
	settings.Scope = s
	return t.UpdateSettings(settings)
}
