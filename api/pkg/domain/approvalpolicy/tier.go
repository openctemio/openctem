// Package approvalpolicy decides who may approve a decision that hides a
// risk (a false positive, an accepted risk, a suppression rule, an exception
// on a remediation task), how many people, how long it may last and what a
// later change of the facts does to it. It is pure: the caller reads the
// facts, the approver pool and the organization's policy on the server and
// passes them in. Design: api/docs/rfcs/RFC-111-approval-policy.md.
//
// The platform sets floors that no organization policy can lower; the
// organization's policy can only add constraints above them (Policy.TierFor
// clamps every tier to its floor, and the property tests prove it).
package approvalpolicy

import (
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Tier says who decides a request.
type Tier string

const (
	// TierSingle: the requester decides alone (only where the organization
	// allows it for a false positive, and only a holder of the approve
	// permission who does not own the asset).
	TierSingle Tier = "single"
	// TierPeer: one other person from the approver pool.
	TierPeer Tier = "peer"
	// TierSecurity: one other person from the security pool (with a recorded
	// fallback to the approver pool), re-authenticated recently.
	TierSecurity Tier = "security"
	// TierDual: two other distinct people, at least one from the security
	// pool, each re-authenticated recently.
	TierDual Tier = "dual"
)

// Tiers lists the tiers from the least to the most demanding.
var Tiers = []Tier{TierSingle, TierPeer, TierSecurity, TierDual}

// Rank orders tiers: a higher rank asks for more. An unknown tier ranks as
// the most demanding.
func (t Tier) Rank() int {
	switch t {
	case TierSingle:
		return 0
	case TierPeer:
		return 1
	case TierSecurity:
		return 2
	}
	return 3
}

// IsValid reports whether t is a known tier.
func (t Tier) IsValid() bool {
	for _, v := range Tiers {
		if t == v {
			return true
		}
	}
	return false
}

// RequiredApprovals is how many people other than the requester must sign
// off (0 for single).
func (t Tier) RequiredApprovals() int {
	switch t {
	case TierSingle:
		return 0
	case TierDual:
		return 2
	}
	return 1
}

// NeedsSecurityPool reports whether a sign-off must come from the security
// pool.
func (t Tier) NeedsSecurityPool() bool { return t == TierSecurity || t == TierDual }

// NeedsStepUp reports whether the platform requires a recent
// re-authentication of the approver.
func (t Tier) NeedsStepUp() bool { return t == TierSecurity || t == TierDual }

// MinNoteLength is the shortest note a request of this tier carries.
func (t Tier) MinNoteLength() int {
	if t.NeedsSecurityPool() {
		return 20
	}
	return 1
}

// ParseTier validates a tier.
func ParseTier(s string) (Tier, error) {
	t := Tier(strings.TrimSpace(s))
	if !t.IsValid() {
		return "", fmt.Errorf("%w: tier must be one of single, peer, security, dual", shared.ErrValidation)
	}
	return t, nil
}

// MaxTier returns the more demanding of a and b.
func MaxTier(a, b Tier) Tier {
	if b.Rank() > a.Rank() {
		return b
	}
	return a
}

// Class is the risk class of a finding (or of the worst finding a rule or
// group covers).
type Class string

const (
	ClassStandard Class = "standard"
	ClassHigh     Class = "high"
	ClassCritical Class = "critical"
)

// Classes lists the classes from the lowest.
var Classes = []Class{ClassStandard, ClassHigh, ClassCritical}

// Rank orders classes; an unknown class ranks as critical.
func (c Class) Rank() int {
	switch c {
	case ClassStandard:
		return 0
	case ClassHigh:
		return 1
	}
	return 2
}

// IsValid reports whether c is a known class.
func (c Class) IsValid() bool {
	return c == ClassStandard || c == ClassHigh || c == ClassCritical
}

// raised is the next class up (critical stays critical).
func (c Class) raised() Class {
	switch c {
	case ClassStandard:
		return ClassHigh
	default:
		return ClassCritical
	}
}

// MaxClass returns the higher of a and b.
func MaxClass(a, b Class) Class {
	if b.Rank() > a.Rank() {
		return b
	}
	return a
}

// Kind is what a request decides.
type Kind string

const (
	// KindFalsePositive: one finding is not a real issue.
	KindFalsePositive Kind = "false_positive"
	// KindAccepted: the risk of one finding is accepted until a date.
	KindAccepted Kind = "accepted"
	// KindRuleFalsePositive: a suppression rule marks matching findings
	// false positives, now and later.
	KindRuleFalsePositive Kind = "rule_false_positive"
	// KindRuleAccepted: a suppression rule accepts the risk of matching
	// findings (accepted-risk and won't-fix rules), now and later.
	KindRuleAccepted Kind = "rule_accepted"
)

// Kinds lists every kind a policy can set a tier for.
var Kinds = []Kind{KindFalsePositive, KindAccepted, KindRuleFalsePositive, KindRuleAccepted}

// IsValid reports whether k is a known kind.
func (k Kind) IsValid() bool {
	for _, v := range Kinds {
		if k == v {
			return true
		}
	}
	return false
}

// IsAcceptance reports whether the kind accepts a risk (it ends, and the
// asset's exposure raises its class).
func (k Kind) IsAcceptance() bool { return k == KindAccepted || k == KindRuleAccepted }

// IsRule reports whether the kind is a suppression rule.
func (k Kind) IsRule() bool { return k == KindRuleFalsePositive || k == KindRuleAccepted }

// cellKey is the policy key of one kind and class ("accepted.high").
func cellKey(k Kind, c Class) string { return string(k) + "." + string(c) }

// Floor is the platform's minimum tier for a kind and class. No
// organization policy goes below it.
//
//   - false positive: single (the organization's false-positive level may be
//     off);
//   - accepted risk: peer, and security from high up (four-eyes on an
//     accepted risk is never off);
//   - suppression rules decide many findings, including future ones: never
//     single; an accepted-risk rule follows the accepted-risk floors.
func Floor(k Kind, c Class) Tier {
	switch k {
	case KindFalsePositive:
		return TierSingle
	case KindRuleFalsePositive:
		return TierPeer
	case KindAccepted, KindRuleAccepted:
		if c == ClassStandard {
			return TierPeer
		}
		return TierSecurity
	}
	return TierDual
}

// Default is the platform's default tier for a kind and class, used when the
// organization's policy sets none. It is at or above the floor; an
// organization may relax it down to the floor (a delayed change).
func Default(k Kind, c Class) Tier {
	switch k {
	case KindFalsePositive:
		return TierPeer
	case KindRuleFalsePositive:
		if c == ClassStandard {
			return TierPeer
		}
		return TierSecurity
	case KindAccepted, KindRuleAccepted:
		switch c {
		case ClassStandard:
			return TierPeer
		case ClassHigh:
			return TierSecurity
		}
		return TierDual
	}
	return TierDual
}
