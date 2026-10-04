// Package attribution decides whether an internet-facing asset belongs to the
// tenant, from typed evidence (RFC-036 §6.4, owner decision O4).
//
// Confidence is the noisy-OR of the positive evidence weights, discounted by
// the negative ones: c = (1 − Π(1 − w⁺)) · Π(1 − w⁻), shown as 0–100. An asset
// is auto-confirmed only when at least one strong rule fired and c ≥ 90;
// otherwise it waits for review (c ≥ 50) or stays a candidate.
//
// An asset with no attribution record is a legacy asset and counts as
// confirmed: everything in the inventory before EASM was put there by the
// tenant, a scan it ran, or an integration it connected.
package attribution

import (
	"fmt"
	"math"
	"sort"
)

// State is an asset's attribution state.
type State string

const (
	// StateConfirmed: the tenant's, and active checks within its tier may run.
	StateConfirmed State = "confirmed"
	// StateNeedsReview: probably the tenant's; a human decides. Passive only.
	StateNeedsReview State = "needs_review"
	// StateCandidate: weak evidence; hidden unless filtered for. Passive only.
	StateCandidate State = "candidate"
	// StateDependency: the tenant's name on someone else's infrastructure
	// (CDN, SaaS). Passive checks and the takeover check only.
	StateDependency State = "dependency"
	// StateMonitorOnly: watched passively by decision.
	StateMonitorOnly State = "monitor_only"
	// StateRejected: not the tenant's.
	StateRejected State = "rejected"
)

// Valid reports whether s is a known state.
func (s State) Valid() bool {
	switch s {
	case StateConfirmed, StateNeedsReview, StateCandidate, StateDependency, StateMonitorOnly, StateRejected:
		return true
	}
	return false
}

// AllowsActiveChecks reports whether a sensor may touch an asset in this
// state (RFC-036 §6.3 active_allowed: confirmed only). The empty state is a
// legacy asset without a record and is treated as confirmed.
func (s State) AllowsActiveChecks() bool {
	return s == "" || s == StateConfirmed
}

// rank orders the automatic states so a re-evaluation only ever raises one.
func (s State) rank() int {
	switch s {
	case StateCandidate:
		return 1
	case StateNeedsReview:
		return 2
	case StateConfirmed:
		return 3
	}
	return 0
}

// Rule is a typed reason to believe (or doubt) that an asset is the tenant's.
type Rule string

// Rules of the starting table (RFC-036 §6.4). Only the rules something
// produces today are listed; the rest arrive with their collectors.
const (
	// RuleVerifiedRoot: the name is at or below a domain the tenant proved it
	// controls with a DNS TXT record.
	RuleVerifiedRoot Rule = "fqdn_under_verified_root"
	// RuleAssertedRoot: the name is below a domain the tenant listed (a domain
	// asset or a scope target) but did not verify.
	RuleAssertedRoot Rule = "fqdn_under_asserted_root"
	// RuleTenantScanned: the tenant scanned or created the asset itself.
	RuleTenantScanned Rule = "tenant_scanned"
)

// Class is the strength class of a rule.
type Class string

const (
	ClassStrong Class = "strong"
	ClassMedium Class = "medium"
	ClassWeak   Class = "weak"
)

type ruleDef struct {
	weight float64 // negative for evidence against
	class  Class
}

var rules = map[Rule]ruleDef{
	RuleVerifiedRoot:  {0.99, ClassStrong},
	RuleTenantScanned: {0.95, ClassStrong},
	RuleAssertedRoot:  {0.85, ClassMedium},
}

// Weight returns the base weight and class of a rule.
func Weight(r Rule) (float64, Class, error) {
	d, ok := rules[r]
	if !ok {
		return 0, "", fmt.Errorf("unknown attribution rule %q", r)
	}
	return d.weight, d.class, nil
}

// AutoConfirmThreshold is O4's bar: at least one strong rule and c ≥ 90.
const AutoConfirmThreshold = 90

// ReviewThreshold separates needs_review from candidate.
const ReviewThreshold = 50

// Decision is the outcome of evaluating an asset's evidence.
type Decision struct {
	State      State
	Confidence int  // 0–100
	Reason     Rule // the strongest positive rule
}

// Evaluate computes confidence and state from the rules that fired. Each rule
// counts once, however many times it was observed: a second sighting of the
// same fact is not new evidence.
func Evaluate(fired []Rule) (Decision, error) {
	seen := map[Rule]bool{}
	pos, neg := 1.0, 1.0
	strong := false
	var reason Rule
	best := -1.0
	ordered := append([]Rule(nil), fired...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	for _, r := range ordered {
		if seen[r] {
			continue
		}
		seen[r] = true
		d, ok := rules[r]
		if !ok {
			return Decision{}, fmt.Errorf("unknown attribution rule %q", r)
		}
		if d.weight >= 0 {
			pos *= 1 - d.weight
			if d.class == ClassStrong {
				strong = true
			}
			if d.weight > best {
				best, reason = d.weight, r
			}
		} else {
			neg *= 1 + d.weight
		}
	}
	c := int(math.Floor((1-pos)*neg*100 + 1e-9))
	dec := Decision{Confidence: c, Reason: reason}
	switch {
	case strong && c >= AutoConfirmThreshold:
		dec.State = StateConfirmed
	case c >= ReviewThreshold:
		dec.State = StateNeedsReview
	default:
		dec.State = StateCandidate
	}
	return dec, nil
}

// Merge decides the state to store given the current record (if any) and a
// fresh automatic decision:
//
//   - a human decision is never overridden by automation;
//   - automation only raises the state (candidate → needs_review →
//     confirmed), never lowers it, so new weak evidence cannot demote a
//     confirmed asset; confidence follows the evidence;
//   - dependency / monitor_only / rejected are only ever set by a human.
func Merge(current *Record, fresh Decision) Decision {
	if current == nil {
		return fresh
	}
	if current.HumanDecided {
		return Decision{State: current.State, Confidence: fresh.Confidence, Reason: current.Reason}
	}
	if current.State.rank() > fresh.State.rank() {
		return Decision{State: current.State, Confidence: max(fresh.Confidence, current.Confidence), Reason: current.Reason}
	}
	return fresh
}

// Record is the stored attribution of one asset.
type Record struct {
	State        State
	Confidence   int
	Reason       Rule
	HumanDecided bool
}

// Evidence is one typed observation supporting (or contradicting) that an
// asset is the tenant's. Technique is how it was found (ADR-004: technique,
// not channel), Source the collector or sensor run that saw it.
type Evidence struct {
	AssetID   string
	Rule      Rule
	Technique string
	Source    string
	Weight    float64
	Observed  map[string]any
}

// Filter values accepted by the asset list (?attribution=) besides the six
// states. Unrecorded matches assets with no attribution record (legacy:
// in the inventory before EASM, counted as confirmed). Unconfirmed is the
// review queue (needs_review and candidate). Approved is what the default
// inventory shows: confirmed (recorded or legacy), dependency and
// monitor_only; it leaves out the review queue and rejected assets.
const (
	FilterUnrecorded  = "unknown"
	FilterUnconfirmed = "unconfirmed"
	FilterApproved    = "approved"
)

// StateFilter is a parsed attribution filter: the stored states to match,
// and whether an asset with no record matches too.
type StateFilter struct {
	States     []State
	Unrecorded bool
}

// ParseFilter expands ?attribution= values into a StateFilter. confirmed
// includes unrecorded assets, matching how the attribution API reports them.
// An empty input returns ok=false (no filter). An unknown value is an error.
func ParseFilter(values []string) (StateFilter, bool, error) {
	var f StateFilter
	seen := map[State]bool{}
	add := func(states ...State) {
		for _, s := range states {
			if !seen[s] {
				seen[s] = true
				f.States = append(f.States, s)
			}
		}
	}
	given := false
	for _, v := range values {
		switch v {
		case "":
			continue
		case FilterUnrecorded:
			f.Unrecorded = true
		case FilterUnconfirmed:
			add(StateNeedsReview, StateCandidate)
		case FilterApproved:
			add(StateConfirmed, StateDependency, StateMonitorOnly)
			f.Unrecorded = true
		default:
			s := State(v)
			if !s.Valid() {
				return StateFilter{}, false, fmt.Errorf("unknown attribution filter %q", v)
			}
			add(s)
			if s == StateConfirmed {
				f.Unrecorded = true
			}
		}
		given = true
	}
	sort.Slice(f.States, func(i, j int) bool { return f.States[i] < f.States[j] })
	return f, given, nil
}
