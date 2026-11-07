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

// What active scans may do to unclassified assets (RFC-054 §16): assets no
// scope entry covers and nobody excluded or rejected.
const (
	UnclassifiedOff       = "off"
	UnclassifiedLowImpact = "low_impact"
	UnclassifiedFull      = "full"
)

// What happens to an address the organization's in-scope names resolve to
// (research/425): added automatically when the organization's own declared
// networks hold it (default), offered to a person, or never suggested.
const (
	AddressAutoStrong = "auto_strong"
	AddressAsk        = "ask"
	AddressNever      = "never"
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
	// (they stay discovered, or wait for review with ReviewBeforeInventory).
	AutoJoinDisabled bool `json:"auto_join_disabled,omitempty"`
	// ConfirmAddsToScopeDisabled stops a person's Confirm from adding the
	// asset's exact scope entry (research/117). The default (false) adds it
	// while scan approval is Off or On; under Strict it never does.
	ConfirmAddsToScopeDisabled bool `json:"confirm_adds_to_scope_disabled,omitempty"`
	// ReviewBeforeInventory keeps the review gate: what discovery finds
	// outside every permanent scope entry waits for a person (needs_review)
	// outside the inventory, instead of joining it as discovered (passive
	// only). Default off. Meant for organizations that run scan
	// approval Strict; it never changes what may be scanned.
	ReviewBeforeInventory bool `json:"review_before_inventory,omitempty"`
	// UnclassifiedScans is what active scans may do to an asset no scope
	// entry covers and nobody excluded or rejected: off (passive only),
	// low_impact (default: the low-impact profile, scopedom.LowImpact) or
	// full (the scan's own tier). The platform guardrails apply in every
	// mode; under the Strict scan approval mode it is off whatever is set.
	UnclassifiedScans string `json:"unclassified_scans,omitempty"`
	// AddressAutoAdd is what happens to an address in-scope names resolve
	// to: auto_strong (default: added as an exact entry when the evidence is
	// strong, through the approval policy), ask (a person decides each) or
	// never (not suggested). Under the Strict scan approval mode nothing is
	// added automatically whatever is set.
	AddressAutoAdd string `json:"address_auto_add,omitempty"`
	// AutoCoverage turns automatic coverage (RFC-093) on or off: the
	// coverage loop starts the capabilities each in-scope asset needs. Nil is
	// the default: on, except while the Strict scan approval mode is in force
	// (owner decision D1).
	AutoCoverage *bool `json:"auto_coverage,omitempty"`
	// InfoCoverage turns the info pass of continuous coverage on or off: the
	// vuln.templates stage at severity info only, on its own slower cadence
	// (InfoCoverageDays). Nil is the default: on.
	InfoCoverage *bool `json:"info_coverage,omitempty"`
	// InfoCoverageDays is the interval of the info pass, 7..90 (0: 30).
	InfoCoverageDays int `json:"info_coverage_days,omitempty"`
	// PathDiscovery turns the platform's path discovery of web services on
	// or off: candidate paths derived from the organization's own
	// inventory, at most one run per origin per 30 days, GET and HEAD only
	// (docs/architecture/web-discovery.md). Nil is the default: on.
	PathDiscovery *bool `json:"path_discovery,omitempty"`
	// CIScopeRequiresProof keeps a CI trust's new repository scope entries
	// inactive until a verified pipeline run under them (opt-in governance,
	// default off: a trust's entries are in effect at once).
	CIScopeRequiresProof bool `json:"ci_scope_requires_proof,omitempty"`
	// OneOffTargets: admins, admins_and_requests (default) or disabled.
	OneOffTargets string `json:"one_off_targets,omitempty"`
	// OneOffMaxDays bounds an expiring entry, 1..30 (0: 7).
	OneOffMaxDays int `json:"one_off_max_days,omitempty"`
	// WideningApprovals is 0, 1 or 2 approvals for a widening; nil is the
	// default min(1, admins-1).
	WideningApprovals *int `json:"widening_approvals,omitempty"`
	// DefaultMaxTier is t0 or t1 ("" = t1). t2 is never a default.
	DefaultMaxTier string `json:"default_max_tier,omitempty"`
	// MaxRangePrefix is the widest address range one scan target may name,
	// as an IPv4 prefix length from 8 to 24 (0 = 16, a /16). IPv6 gets the
	// same address count (/16 -> /112). A range wider than a /16 is opt-in:
	// raising it (a lower prefix) widens what one scan may sweep and is
	// audited at high severity with the administrators told (RFC-151).
	MaxRangePrefix int `json:"max_range_prefix,omitempty"`

	// Owner-only fields (IntrusiveScopeSettings): PUT /scope/settings keeps
	// them; only PUT /scope/settings/intrusive changes them.

	// T2MaxDuration is the longest a t2 entry may last: 7d, 30d, 90d, 365d
	// or permanent ("" = 30d).
	T2MaxDuration string `json:"t2_max_duration,omitempty"`
	// T2AttestationDays: how often a long t2 entry is confirmed, 30..180
	// (0 = 90).
	T2AttestationDays int `json:"t2_attestation_days,omitempty"`
}

// Range target bounds (RFC-151): the IPv4 prefix length of the widest
// range one scan target may name. A /8 is the platform limit; a /16 is the
// default of every organization, and anything wider is opt-in.
const (
	MinRangePrefix     = 8
	MaxRangePrefix     = 24
	DefaultRangePrefix = 16
)

// RangePrefix returns the widest range prefix with its default (/16).
func (s ScopeSettings) RangePrefix() int {
	if s.MaxRangePrefix <= 0 {
		return DefaultRangePrefix
	}
	return s.MaxRangePrefix
}

// RangeHostBits is the widest range in host bits (32 - RangePrefix): 16 by
// default, 24 for a /8, the same address count for both families.
func (s ScopeSettings) RangeHostBits() int { return 32 - s.RangePrefix() }

// RangeWidened reports whether a scope settings change raised the widest
// range one scan target may name (a lower max_range_prefix). Lowering it
// narrows and needs nothing more.
func RangeWidened(before, after ScopeSettings) bool {
	return after.RangePrefix() < before.RangePrefix()
}

// Attestation bounds (RFC-054 §12.5).
const (
	MinT2AttestationDays     = 30
	MaxT2AttestationDays     = 180
	DefaultT2AttestationDays = 90
)

// AttestationDays returns the attestation period with its default.
func (s ScopeSettings) AttestationDays() int {
	if s.T2AttestationDays <= 0 {
		return DefaultT2AttestationDays
	}
	return s.T2AttestationDays
}

// IntrusiveScopeSettings are the owner-only scope settings (RFC-054 §12.4).
type IntrusiveScopeSettings struct {
	T2MaxDuration     string
	T2AttestationDays int
}

// WithIntrusive returns s with the owner-only fields of i.
func (s ScopeSettings) WithIntrusive(i IntrusiveScopeSettings) ScopeSettings {
	s.T2MaxDuration = i.T2MaxDuration
	s.T2AttestationDays = i.T2AttestationDays
	return s
}

// Intrusive returns the owner-only fields of s.
func (s ScopeSettings) Intrusive() IntrusiveScopeSettings {
	return IntrusiveScopeSettings{T2MaxDuration: s.T2MaxDuration, T2AttestationDays: s.T2AttestationDays}
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
	switch s.UnclassifiedScans {
	case "", UnclassifiedOff, UnclassifiedLowImpact, UnclassifiedFull:
	default:
		return fmt.Errorf("%w: unclassified_scans must be off, low_impact or full", shared.ErrValidation)
	}
	if s.InfoCoverageDays != 0 && (s.InfoCoverageDays < MinInfoCoverageDays || s.InfoCoverageDays > MaxInfoCoverageDays) {
		return fmt.Errorf("%w: info_coverage_days must be between %d and %d", shared.ErrValidation, MinInfoCoverageDays, MaxInfoCoverageDays)
	}
	switch s.AddressAutoAdd {
	case "", AddressAutoStrong, AddressAsk, AddressNever:
	default:
		return fmt.Errorf("%w: address_auto_add must be auto_strong, ask or never", shared.ErrValidation)
	}
	if s.MaxRangePrefix != 0 && (s.MaxRangePrefix < MinRangePrefix || s.MaxRangePrefix > MaxRangePrefix) {
		return fmt.Errorf("%w: max_range_prefix must be between %d and %d", shared.ErrValidation, MinRangePrefix, MaxRangePrefix)
	}
	switch s.DefaultMaxTier {
	case "", "t0", "t1":
	default:
		return fmt.Errorf("%w: default_max_tier must be t0 or t1", shared.ErrValidation)
	}
	if _, ok := t2MaxDays[s.T2MaxDuration]; !ok && s.T2MaxDuration != "" && s.T2MaxDuration != T2MaxPermanent {
		return fmt.Errorf("%w: t2_max_duration must be 7d, 30d, 90d, 365d or permanent", shared.ErrValidation)
	}
	if s.T2AttestationDays != 0 && (s.T2AttestationDays < MinT2AttestationDays || s.T2AttestationDays > MaxT2AttestationDays) {
		return fmt.Errorf("%w: t2_attestation_days must be between %d and %d", shared.ErrValidation, MinT2AttestationDays, MaxT2AttestationDays)
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

// Unclassified returns the unclassified-scans setting with its default
// (low_impact). The Strict scan approval mode turns it off; the caller
// applies that (scangov).
func (s ScopeSettings) Unclassified() string {
	if s.UnclassifiedScans == "" {
		return UnclassifiedLowImpact
	}
	return s.UnclassifiedScans
}

// AddressMode returns the address setting with its default (auto_strong).
// The Strict scan approval mode stops automatic adds; AddressModeIn applies
// it.
func (s ScopeSettings) AddressMode() string {
	if s.AddressAutoAdd == "" {
		return AddressAutoStrong
	}
	return s.AddressAutoAdd
}

// AddressModeIn is the address mode in force: auto_strong becomes ask while
// the Strict scan approval mode is in force.
func (s ScopeSettings) AddressModeIn(strict bool) string {
	m := s.AddressMode()
	if strict && m == AddressAutoStrong {
		return AddressAsk
	}
	return m
}

// AutoCoverageOn reports whether automatic coverage runs: the explicit
// choice, else on unless the Strict scan approval mode is in force.
func (s ScopeSettings) AutoCoverageOn(strict bool) bool {
	if s.AutoCoverage != nil {
		return *s.AutoCoverage
	}
	return !strict
}

// Bounds and default of the info pass interval, in days.
const (
	MinInfoCoverageDays     = 7
	MaxInfoCoverageDays     = 90
	DefaultInfoCoverageDays = 30
)

// InfoCoverageOn reports whether the info pass runs (default on).
func (s ScopeSettings) InfoCoverageOn() bool {
	return s.InfoCoverage == nil || *s.InfoCoverage
}

// InfoCoverageEvery returns the info pass interval in days with its default.
func (s ScopeSettings) InfoCoverageEvery() int {
	if s.InfoCoverageDays == 0 {
		return DefaultInfoCoverageDays
	}
	return s.InfoCoverageDays
}

// PathDiscoveryOn reports whether path discovery runs (default on).
func (s ScopeSettings) PathDiscoveryOn() bool {
	return s.PathDiscovery == nil || *s.PathDiscovery
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
