// Package scanwindow is the domain of scan window policies: when scans may
// touch which targets (docs/rfcs/RFC-067-scan-window-policies.md,
// docs/architecture/scan-windows.md).
//
// A policy selects targets and is an allow window (scan them only inside its
// windows) or a blackout (never inside). Bug-bounty program testing windows
// are evaluated as allow sources too (evaluate.go). This file validates what
// is stored; evaluate.go decides.
package scanwindow

import (
	"fmt"
	"slices"
	"strings"
	"time"

	// The tz database is embedded so evaluation never depends on the host
	// image having /usr/share/zoneinfo.
	_ "time/tzdata"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Kind is what a policy does to the targets it selects.
type Kind string

const (
	// KindAllow: the targets may be scanned only inside the windows.
	KindAllow Kind = "allow"
	// KindBlackout: the targets are never scanned inside the windows.
	KindBlackout Kind = "blackout"
)

// Probe tiers a policy can govern from (RFC-054): 0 every tool, 1 active and
// intrusive tools, 2 intrusive tools only.
const (
	TierAll       = 0
	TierActive    = 1
	TierIntrusive = 2
)

// Caps.
const (
	MaxPoliciesPerTenant = 50
	MaxSlots             = 14
	MaxOneOffs           = 20
	MaxOneOffDuration    = 31 * 24 * time.Hour
	MaxGraceMinutes      = 240
	DefaultGraceMinutes  = 15
	MaxRateLimitRPS      = 100000
	MaxConcurrent        = 1000
	maxSelectorValues    = 50
	maxTagLen            = 100
	maxNameLen           = 100
	maxDescriptionLen    = 1000
	maxTimezoneLen       = 64
	minutesPerDay        = 24 * 60
)

var (
	// ErrNotFound is returned for a policy that is not the tenant's.
	ErrNotFound = shared.NewDomainError("SCAN_WINDOW_POLICY_NOT_FOUND", "scan window policy not found", shared.ErrNotFound)
	// ErrTooMany is returned when the tenant has MaxPoliciesPerTenant policies.
	ErrTooMany = shared.NewDomainError("TOO_MANY_SCAN_WINDOW_POLICIES",
		fmt.Sprintf("an organization can have at most %d scan window policies", MaxPoliciesPerTenant), shared.ErrValidation)
	// ErrUnknownReference is returned for a selector id that is not one of
	// the organization's own objects (whether or not it exists elsewhere).
	ErrUnknownReference = shared.NewDomainError("SCAN_WINDOW_UNKNOWN_REFERENCE",
		"the selector names a group, business unit, scope entry, zone or program this organization does not have", shared.ErrValidation)
)

// Slot is a weekly window: on the ISO days (1 Monday ... 7 Sunday), from
// Start to End, "HH:MM" wall-clock in the policy's time zone. An End not
// after Start runs past midnight; equal times are 24 hours from Start.
type Slot struct {
	Days  []int  `json:"days"`
	Start string `json:"start"`
	End   string `json:"end"`
}

// OneOff is a dated window between two instants (end exclusive).
type OneOff struct {
	StartsAt time.Time `json:"starts_at"`
	EndsAt   time.Time `json:"ends_at"`
}

// Selector says which targets a policy governs: every given dimension must
// match (AND), any value of a dimension matches it (OR). Empty selects every
// target of the organization.
type Selector struct {
	Tags            []string `json:"tags,omitempty"`
	AssetGroupIDs   []string `json:"asset_group_ids,omitempty"`
	AssetTypes      []string `json:"asset_types,omitempty"`
	Criticalities   []string `json:"criticalities,omitempty"`
	BusinessUnitIDs []string `json:"business_unit_ids,omitempty"`
	ScopeTargetIDs  []string `json:"scope_target_ids,omitempty"`
	ScanZoneIDs     []string `json:"scan_zone_ids,omitempty"`
	ProgramIDs      []string `json:"program_ids,omitempty"`
}

// Empty reports whether the selector selects every target.
func (s Selector) Empty() bool {
	return !s.UsesAssets() && !s.UsesScope() && len(s.ScanZoneIDs) == 0
}

// UsesAssets reports whether matching needs the assets behind the targets.
func (s Selector) UsesAssets() bool {
	return len(s.Tags)+len(s.AssetGroupIDs)+len(s.AssetTypes)+len(s.Criticalities)+len(s.BusinessUnitIDs) > 0
}

// UsesScope reports whether matching needs the scope entries and programs
// covering the targets.
func (s Selector) UsesScope() bool {
	return len(s.ScopeTargetIDs)+len(s.ProgramIDs) > 0
}

// Policy is one scan window policy of a tenant.
type Policy struct {
	ID          shared.ID
	TenantID    shared.ID
	Name        string
	Description string
	Enabled     bool
	Kind        Kind
	// MinTier is the lowest probe tier the policy governs (TierAll,
	// TierActive, TierIntrusive).
	MinTier  int
	Selector Selector
	// Timezone is the IANA zone of the weekly slots.
	Timezone string
	Slots    []Slot
	OneOffs  []OneOff
	// GraceMinutes is how long a running chunk may continue after its
	// window closes.
	GraceMinutes int
	// RateLimitRPS and MaxConcurrent are optional caps of an allow policy
	// inside its windows (0: none).
	RateLimitRPS  int
	MaxConcurrent int
	CreatedBy     *shared.ID
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Spec is what a client sets on a policy.
type Spec struct {
	Name          string
	Description   string
	Enabled       bool
	Kind          Kind
	MinTier       int
	Selector      Selector
	Timezone      string
	Slots         []Slot
	OneOffs       []OneOff
	GraceMinutes  int
	RateLimitRPS  int
	MaxConcurrent int
}

// NewPolicy validates spec and returns a new policy of the tenant.
func NewPolicy(tenantID shared.ID, spec Spec, createdBy *shared.ID, now time.Time) (*Policy, error) {
	p := &Policy{ID: shared.NewID(), TenantID: tenantID, CreatedBy: createdBy, CreatedAt: now, UpdatedAt: now}
	if err := p.apply(spec); err != nil {
		return nil, err
	}
	return p, nil
}

// Update replaces the policy's settings with spec; nothing changes on error.
func (p *Policy) Update(spec Spec, now time.Time) error {
	next := *p
	if err := next.apply(spec); err != nil {
		return err
	}
	next.UpdatedAt = now
	*p = next
	return nil
}

// Spec returns the policy's settings, for a partial update.
func (p *Policy) Spec() Spec {
	return Spec{
		Name: p.Name, Description: p.Description, Enabled: p.Enabled, Kind: p.Kind, MinTier: p.MinTier,
		Selector: cloneSelector(p.Selector), Timezone: p.Timezone,
		Slots: slices.Clone(p.Slots), OneOffs: slices.Clone(p.OneOffs),
		GraceMinutes: p.GraceMinutes, RateLimitRPS: p.RateLimitRPS, MaxConcurrent: p.MaxConcurrent,
	}
}

func (p *Policy) apply(spec Spec) error {
	name := strings.TrimSpace(spec.Name)
	if name == "" || len([]rune(name)) > maxNameLen {
		return invalid(fmt.Sprintf("name must be 1 to %d characters", maxNameLen))
	}
	if len([]rune(spec.Description)) > maxDescriptionLen {
		return invalid(fmt.Sprintf("description must be at most %d characters", maxDescriptionLen))
	}
	if spec.Kind != KindAllow && spec.Kind != KindBlackout {
		return invalid(`kind must be "allow" or "blackout"`)
	}
	if spec.MinTier < TierAll || spec.MinTier > TierIntrusive {
		return invalid("min_tier must be 0 (every tool), 1 (active and intrusive) or 2 (intrusive)")
	}
	tz, err := ValidateTimezone(spec.Timezone)
	if err != nil {
		return err
	}
	slots, err := normalizeSlots(spec.Slots)
	if err != nil {
		return err
	}
	oneOffs, err := normalizeOneOffs(spec.OneOffs)
	if err != nil {
		return err
	}
	if len(slots) == 0 && len(oneOffs) == 0 {
		return invalid("a policy needs at least one weekly slot or one dated window")
	}
	sel, err := normalizeSelector(spec.Selector)
	if err != nil {
		return err
	}
	if spec.GraceMinutes < 0 || spec.GraceMinutes > MaxGraceMinutes {
		return invalid(fmt.Sprintf("grace_minutes must be 0 to %d", MaxGraceMinutes))
	}
	if spec.RateLimitRPS < 0 || spec.RateLimitRPS > MaxRateLimitRPS {
		return invalid(fmt.Sprintf("rate_limit_rps must be 0 to %d", MaxRateLimitRPS))
	}
	if spec.MaxConcurrent < 0 || spec.MaxConcurrent > MaxConcurrent {
		return invalid(fmt.Sprintf("max_concurrent must be 0 to %d", MaxConcurrent))
	}
	if spec.Kind == KindBlackout && (spec.RateLimitRPS > 0 || spec.MaxConcurrent > 0) {
		return invalid("rate_limit_rps and max_concurrent apply inside an allow window; a blackout has none")
	}
	p.Name, p.Description, p.Enabled, p.Kind, p.MinTier = name, spec.Description, spec.Enabled, spec.Kind, spec.MinTier
	p.Selector, p.Timezone, p.Slots, p.OneOffs = sel, tz, slots, oneOffs
	p.GraceMinutes, p.RateLimitRPS, p.MaxConcurrent = spec.GraceMinutes, spec.RateLimitRPS, spec.MaxConcurrent
	return nil
}

// ValidateTimezone returns the IANA zone name or a validation error.
func ValidateTimezone(tz string) (string, error) {
	tz = strings.TrimSpace(tz)
	if tz == "" || len(tz) > maxTimezoneLen || strings.EqualFold(tz, "local") {
		return "", invalid("timezone must be an IANA time zone name such as Europe/Berlin")
	}
	if _, err := time.LoadLocation(tz); err != nil {
		return "", invalid(fmt.Sprintf("unknown timezone %q", clip(tz)))
	}
	return tz, nil
}

func normalizeSlots(in []Slot) ([]Slot, error) {
	if len(in) > MaxSlots {
		return nil, invalid(fmt.Sprintf("a policy has at most %d weekly slots", MaxSlots))
	}
	out := make([]Slot, 0, len(in))
	for _, s := range in {
		days, err := normalizeDays(s.Days)
		if err != nil {
			return nil, err
		}
		start, err := ParseMinute(s.Start)
		if err != nil {
			return nil, invalid("slot start: " + err.Error())
		}
		end, err := ParseMinute(s.End)
		if err != nil {
			return nil, invalid("slot end: " + err.Error())
		}
		out = append(out, Slot{Days: days, Start: FormatMinute(start), End: FormatMinute(end)})
	}
	return out, nil
}

func normalizeOneOffs(in []OneOff) ([]OneOff, error) {
	if len(in) > MaxOneOffs {
		return nil, invalid(fmt.Sprintf("a policy has at most %d dated windows", MaxOneOffs))
	}
	out := make([]OneOff, 0, len(in))
	for _, o := range in {
		if o.StartsAt.IsZero() || o.EndsAt.IsZero() {
			return nil, invalid("a dated window needs starts_at and ends_at")
		}
		start, end := o.StartsAt.UTC(), o.EndsAt.UTC()
		if !end.After(start) {
			return nil, invalid("a dated window must end after it starts")
		}
		if end.Sub(start) > MaxOneOffDuration {
			return nil, invalid("a dated window lasts at most 31 days")
		}
		out = append(out, OneOff{StartsAt: start, EndsAt: end})
	}
	slices.SortFunc(out, func(a, b OneOff) int { return a.StartsAt.Compare(b.StartsAt) })
	return out, nil
}

func normalizeDays(days []int) ([]int, error) {
	if len(days) == 0 {
		return nil, invalid("a weekly slot needs at least one day (1 Monday ... 7 Sunday)")
	}
	out := make([]int, 0, len(days))
	for _, d := range days {
		if d < 1 || d > 7 {
			return nil, invalid("days must be ISO weekdays, 1 (Monday) to 7 (Sunday)")
		}
		if !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	slices.Sort(out)
	return out, nil
}

func normalizeSelector(s Selector) (Selector, error) {
	var out Selector
	var err error
	if out.Tags, err = normalizeTags(s.Tags); err != nil {
		return out, err
	}
	for _, f := range []struct {
		name string
		in   []string
		out  *[]string
	}{
		{"asset_group_ids", s.AssetGroupIDs, &out.AssetGroupIDs},
		{"business_unit_ids", s.BusinessUnitIDs, &out.BusinessUnitIDs},
		{"scope_target_ids", s.ScopeTargetIDs, &out.ScopeTargetIDs},
		{"scan_zone_ids", s.ScanZoneIDs, &out.ScanZoneIDs},
		{"program_ids", s.ProgramIDs, &out.ProgramIDs},
	} {
		if *f.out, err = normalizeIDs(f.name, f.in); err != nil {
			return out, err
		}
	}
	if len(s.AssetTypes) > maxSelectorValues {
		return out, invalid(fmt.Sprintf("asset_types has at most %d values", maxSelectorValues))
	}
	for _, t := range s.AssetTypes {
		at := asset.AssetType(strings.ToLower(strings.TrimSpace(t)))
		if !at.IsStored() {
			return out, invalid(fmt.Sprintf("%q is not an asset type", clip(t)))
		}
		if !slices.Contains(out.AssetTypes, string(at)) {
			out.AssetTypes = append(out.AssetTypes, string(at))
		}
	}
	if len(s.Criticalities) > maxSelectorValues {
		return out, invalid(fmt.Sprintf("criticalities has at most %d values", maxSelectorValues))
	}
	for _, c := range s.Criticalities {
		cr, perr := asset.ParseCriticality(strings.TrimSpace(c))
		if perr != nil {
			return out, invalid(fmt.Sprintf("%q is not a criticality", clip(c)))
		}
		if !slices.Contains(out.Criticalities, string(cr)) {
			out.Criticalities = append(out.Criticalities, string(cr))
		}
	}
	return out, nil
}

func normalizeTags(in []string) ([]string, error) {
	if len(in) > maxSelectorValues {
		return nil, invalid(fmt.Sprintf("tags has at most %d values", maxSelectorValues))
	}
	var out []string
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" || len([]rune(t)) > maxTagLen {
			return nil, invalid(fmt.Sprintf("a tag is 1 to %d characters", maxTagLen))
		}
		if !slices.ContainsFunc(out, func(o string) bool { return strings.EqualFold(o, t) }) {
			out = append(out, t)
		}
	}
	return out, nil
}

func normalizeIDs(field string, in []string) ([]string, error) {
	if len(in) > maxSelectorValues {
		return nil, invalid(fmt.Sprintf("%s has at most %d values", field, maxSelectorValues))
	}
	var out []string
	for _, raw := range in {
		id, err := shared.IDFromString(strings.TrimSpace(raw))
		if err != nil {
			return nil, invalid(fmt.Sprintf("%s: %q is not an id", field, clip(raw)))
		}
		if !slices.Contains(out, id.String()) {
			out = append(out, id.String())
		}
	}
	return out, nil
}

func cloneSelector(s Selector) Selector {
	return Selector{
		Tags: slices.Clone(s.Tags), AssetGroupIDs: slices.Clone(s.AssetGroupIDs), AssetTypes: slices.Clone(s.AssetTypes),
		Criticalities: slices.Clone(s.Criticalities), BusinessUnitIDs: slices.Clone(s.BusinessUnitIDs),
		ScopeTargetIDs: slices.Clone(s.ScopeTargetIDs), ScanZoneIDs: slices.Clone(s.ScanZoneIDs),
		ProgramIDs: slices.Clone(s.ProgramIDs),
	}
}

// ParseMinute parses "HH:MM" (00:00 to 23:59) into minutes after midnight.
func ParseMinute(s string) (int, error) {
	t, err := time.Parse("15:04", strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("must be HH:MM (00:00 to 23:59)")
	}
	return t.Hour()*60 + t.Minute(), nil
}

// FormatMinute formats minutes after midnight as "HH:MM".
func FormatMinute(m int) string {
	m = ((m % minutesPerDay) + minutesPerDay) % minutesPerDay
	return fmt.Sprintf("%02d:%02d", m/60, m%60)
}

func clip(s string) string {
	if r := []rune(s); len(r) > 64 {
		return string(r[:64]) + "…"
	}
	return s
}

func invalid(msg string) error {
	return shared.NewDomainError("INVALID_SCAN_WINDOW_POLICY", msg, shared.ErrValidation)
}
