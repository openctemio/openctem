package approvalpolicy

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Material-change behavior of an accepted risk.
const (
	// AcceptedEndOnTierRise (floor): the acceptance ends when the tier the
	// finding needs now is above the decided one, or its cap now ends sooner;
	// any other change raises a review flag.
	AcceptedEndOnTierRise = "end_on_tier_rise"
	// AcceptedEndOnAnyChange: any material change ends the acceptance.
	AcceptedEndOnAnyChange = "end_on_any_change"
)

// Material-change behavior of a false positive one person decided.
const (
	// SinglePersonFPFlag (floor): a review flag; the decision stands.
	SinglePersonFPFlag = "flag"
	// SinglePersonFPRevoke: the false positive is withdrawn and the finding
	// is open again.
	SinglePersonFPRevoke = "revoke"
)

// PlatformDecideWithin is how long a pending request waits for a decision.
const PlatformDecideWithin = 14 * 24 * time.Hour

// MaxPolicyDays bounds the day counts of a policy.
const (
	maxDecideWithinDays = 14
	maxAcceptanceDays   = 365
)

// MaterialChangePolicy says what a material change does to a decision.
type MaterialChangePolicy struct {
	Accepted       string `json:"accepted,omitempty"`
	SinglePersonFP string `json:"single_person_fp,omitempty"`
}

// Policy is an organization's approval policy. The zero value is the
// platform default. Every field can only make a decision stricter than the
// platform floor; Validate refuses anything else and TierFor clamps.
type Policy struct {
	// Tiers sets a tier per "<kind>.<class>" ("accepted.high": "dual").
	// A cell may sit below the platform default, never below the floor.
	Tiers map[string]Tier `json:"tiers,omitempty"`
	// SecurityPoolGroupID is the group that forms the security pool.
	SecurityPoolGroupID string `json:"security_pool_group_id,omitempty"`
	// SecurityPoolStrict: no fallback to the approver pool when nobody in
	// the security pool is eligible.
	SecurityPoolStrict bool `json:"security_pool_strict,omitempty"`
	// ExcludeAssignee: the finding's assignee may not approve.
	ExcludeAssignee bool `json:"exclude_assignee,omitempty"`
	// StepUpAllTiers: the peer approver re-authenticates too.
	StepUpAllTiers bool `json:"step_up_all_tiers,omitempty"`
	// MaxAcceptanceDays caps an accepted risk per class, below the platform
	// cap (0 or absent: the platform cap).
	MaxAcceptanceDays map[Class]int `json:"max_acceptance_days,omitempty"`
	// DecideWithinDays is how long a pending request waits (1..14; 0: 14).
	DecideWithinDays int `json:"decide_within_days,omitempty"`
	// EPSSThreshold is the EPSS score from which a finding is high
	// (0.01..0.5; 0: the platform's 0.5).
	EPSSThreshold float64 `json:"epss_threshold,omitempty"`
	// OnMaterialChange says what a material change does.
	OnMaterialChange MaterialChangePolicy `json:"on_material_change,omitempty"`
}

// Validate refuses a policy that would go below a floor or out of range.
func (p Policy) Validate() error {
	for key, t := range p.Tiers {
		k, c, ok := parseCellKey(key)
		if !ok {
			return fmt.Errorf("%w: unknown policy cell %q (use <kind>.<class>)", shared.ErrValidation, key)
		}
		if !t.IsValid() {
			return fmt.Errorf("%w: tier of %s must be one of single, peer, security, dual", shared.ErrValidation, key)
		}
		if t.Rank() < Floor(k, c).Rank() {
			return fmt.Errorf("%w: %s cannot be below the platform floor %s", shared.ErrValidation, key, Floor(k, c))
		}
	}
	if p.SecurityPoolGroupID != "" {
		if _, err := shared.IDFromString(p.SecurityPoolGroupID); err != nil {
			return fmt.Errorf("%w: security_pool_group_id must be a group id", shared.ErrValidation)
		}
	}
	if p.SecurityPoolStrict && p.SecurityPoolGroupID == "" {
		return fmt.Errorf("%w: security_pool_strict needs a security pool group", shared.ErrValidation)
	}
	for c, d := range p.MaxAcceptanceDays {
		if !c.IsValid() {
			return fmt.Errorf("%w: unknown class %q in max_acceptance_days", shared.ErrValidation, c)
		}
		if d < 1 || d > maxAcceptanceDays {
			return fmt.Errorf("%w: max_acceptance_days.%s must be 1 to %d", shared.ErrValidation, c, maxAcceptanceDays)
		}
	}
	if p.DecideWithinDays < 0 || p.DecideWithinDays > maxDecideWithinDays {
		return fmt.Errorf("%w: decide_within_days must be 1 to %d", shared.ErrValidation, maxDecideWithinDays)
	}
	if p.EPSSThreshold != 0 && (p.EPSSThreshold < MinEPSSThreshold || p.EPSSThreshold > PlatformEPSSThreshold) {
		return fmt.Errorf("%w: epss_threshold must be %.2f to %.2f", shared.ErrValidation, MinEPSSThreshold, PlatformEPSSThreshold)
	}
	switch p.OnMaterialChange.Accepted {
	case "", AcceptedEndOnTierRise, AcceptedEndOnAnyChange:
	default:
		return fmt.Errorf("%w: on_material_change.accepted must be %s or %s", shared.ErrValidation, AcceptedEndOnTierRise, AcceptedEndOnAnyChange)
	}
	switch p.OnMaterialChange.SinglePersonFP {
	case "", SinglePersonFPFlag, SinglePersonFPRevoke:
	default:
		return fmt.Errorf("%w: on_material_change.single_person_fp must be %s or %s", shared.ErrValidation, SinglePersonFPFlag, SinglePersonFPRevoke)
	}
	return nil
}

// Normalized returns p with defaults spelled out as zero values (so two
// policies that mean the same compare equal): cells equal to the platform
// default are dropped, material-change floors are empty.
func (p Policy) Normalized() Policy {
	out := p
	out.Tiers = nil
	for key, t := range p.Tiers {
		k, c, ok := parseCellKey(key)
		if !ok || t == Default(k, c) {
			continue
		}
		if out.Tiers == nil {
			out.Tiers = map[string]Tier{}
		}
		out.Tiers[key] = t
	}
	out.MaxAcceptanceDays = nil
	for c, d := range p.MaxAcceptanceDays {
		if d <= 0 || d >= maxAcceptanceDays {
			continue
		}
		if out.MaxAcceptanceDays == nil {
			out.MaxAcceptanceDays = map[Class]int{}
		}
		out.MaxAcceptanceDays[c] = d
	}
	if out.DecideWithinDays >= maxDecideWithinDays {
		out.DecideWithinDays = 0
	}
	if out.EPSSThreshold >= PlatformEPSSThreshold {
		out.EPSSThreshold = 0
	}
	if out.OnMaterialChange.Accepted == AcceptedEndOnTierRise {
		out.OnMaterialChange.Accepted = ""
	}
	if out.OnMaterialChange.SinglePersonFP == SinglePersonFPFlag {
		out.OnMaterialChange.SinglePersonFP = ""
	}
	out.SecurityPoolGroupID = strings.ToLower(strings.TrimSpace(out.SecurityPoolGroupID))
	return out
}

func parseCellKey(key string) (Kind, Class, bool) {
	kind, class, ok := strings.Cut(key, ".")
	if !ok {
		return "", "", false
	}
	k, c := Kind(kind), Class(class)
	if !k.IsValid() || !c.IsValid() {
		return "", "", false
	}
	return k, c, true
}

// TierFor is the tier the policy asks for a kind and class: the
// organization's cell or the platform default, never below the floor. For a
// false positive the organization's false-positive level is applied by
// Evaluate on top of this (the level may lower the default to single).
func (p Policy) TierFor(k Kind, c Class) Tier {
	t, ok := p.Tiers[cellKey(k, c)]
	if !ok || !t.IsValid() {
		t = Default(k, c)
	}
	return MaxTier(Floor(k, c), t)
}

// cellSet reports whether the organization set the cell explicitly.
func (p Policy) cellSet(k Kind, c Class) bool {
	t, ok := p.Tiers[cellKey(k, c)]
	return ok && t.IsValid()
}

// EPSS is the threshold in force.
func (p Policy) EPSS() float64 {
	if p.EPSSThreshold <= 0 || p.EPSSThreshold > PlatformEPSSThreshold {
		return PlatformEPSSThreshold
	}
	return p.EPSSThreshold
}

// DecideWithin is how long a pending request waits.
func (p Policy) DecideWithin() time.Duration {
	if p.DecideWithinDays <= 0 || p.DecideWithinDays > maxDecideWithinDays {
		return PlatformDecideWithin
	}
	return time.Duration(p.DecideWithinDays) * 24 * time.Hour
}

// AcceptanceCap is the longest an accepted risk with these facts may last:
// the platform cap by priority and KEV, or the organization's cap when
// shorter. The organization's cap of a class also bounds every higher class
// (a riskier finding is never accepted for longer than a less risky one).
func (p Policy) AcceptanceCap(f Facts) time.Duration {
	limit := PlatformAcceptanceCap(f.PriorityClass, f.KEV)
	class, _ := ClassOf(KindAccepted, f, p.EPSS())
	for _, c := range Classes {
		if c.Rank() > class.Rank() {
			break
		}
		if d, ok := p.MaxAcceptanceDays[c]; ok && d > 0 {
			if own := time.Duration(d) * 24 * time.Hour; own < limit {
				limit = own
			}
		}
	}
	return limit
}

func minPositive(a, b int) int {
	switch {
	case a <= 0:
		return b
	case b <= 0:
		return a
	case a < b:
		return a
	}
	return b
}

func minPositiveFloat(a, b float64) float64 {
	switch {
	case a <= 0:
		return b
	case b <= 0:
		return a
	case a < b:
		return a
	}
	return b
}

// Stricter combines two policies field by field into the stricter one. A
// different security pool group is not "stricter": the current group (a)
// is kept.
func Stricter(a, b Policy) Policy {
	out := Policy{
		SecurityPoolStrict: a.SecurityPoolStrict || b.SecurityPoolStrict,
		ExcludeAssignee:    a.ExcludeAssignee || b.ExcludeAssignee,
		StepUpAllTiers:     a.StepUpAllTiers || b.StepUpAllTiers,
		DecideWithinDays:   minPositive(a.DecideWithinDays, b.DecideWithinDays),
		EPSSThreshold:      minPositiveFloat(a.EPSSThreshold, b.EPSSThreshold),
	}
	switch {
	case a.SecurityPoolGroupID != "":
		out.SecurityPoolGroupID = a.SecurityPoolGroupID
	default:
		out.SecurityPoolGroupID = b.SecurityPoolGroupID
	}
	for _, k := range Kinds {
		for _, c := range Classes {
			if !a.cellSet(k, c) && !b.cellSet(k, c) {
				continue
			}
			if out.Tiers == nil {
				out.Tiers = map[string]Tier{}
			}
			out.Tiers[cellKey(k, c)] = MaxTier(a.TierFor(k, c), b.TierFor(k, c))
		}
	}
	for _, c := range Classes {
		if d := minPositive(a.MaxAcceptanceDays[c], b.MaxAcceptanceDays[c]); d > 0 {
			if out.MaxAcceptanceDays == nil {
				out.MaxAcceptanceDays = map[Class]int{}
			}
			out.MaxAcceptanceDays[c] = d
		}
	}
	if a.OnMaterialChange.Accepted == AcceptedEndOnAnyChange || b.OnMaterialChange.Accepted == AcceptedEndOnAnyChange {
		out.OnMaterialChange.Accepted = AcceptedEndOnAnyChange
	}
	if a.OnMaterialChange.SinglePersonFP == SinglePersonFPRevoke || b.OnMaterialChange.SinglePersonFP == SinglePersonFPRevoke {
		out.OnMaterialChange.SinglePersonFP = SinglePersonFPRevoke
	}
	return out.Normalized()
}

// Relaxes reports whether moving from current to next relaxes anything
// (next is laxer than current in at least one field). Such a change waits
// RelaxationDelay; a change that only tightens applies at once.
func Relaxes(current, next Policy) bool {
	return !reflect.DeepEqual(Stricter(current, next), next.Normalized())
}

// RelaxationDelay is how long a relaxing change waits before it takes
// effect (raising takes effect at once).
const RelaxationDelay = 24 * time.Hour
