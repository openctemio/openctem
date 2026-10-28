package aianalysis

import (
	"encoding/json"

	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
)

// ComputeDirection decides what applying a normalized payload does to risk,
// from the finding's facts read on the server. The model's own opinion of
// the direction is never an input (NormalizePayload refuses such a field).
//
//   - severity: raises_risk when the target is above the current severity
//     (approvalpolicy.Signals), lowers_risk when below; the same severity is
//     additive (a confirmation).
//   - verdict: likely_false_positive lowers risk (it asks to close); true
//     positive and needs info add information.
//   - remediation steps and summaries are additive.
//
// Anything that cannot be decoded is treated as lowering risk, the most
// guarded direction.
func ComputeDirection(k Kind, payload json.RawMessage, before approvalpolicy.Facts) Direction {
	switch k {
	case KindSeverity:
		var p SeverityPayload
		if json.Unmarshal(payload, &p) != nil {
			return DirectionLowersRisk
		}
		after := before
		after.Severity = p.Severity
		if len(approvalpolicy.Signals(before, after, approvalpolicy.PlatformEPSSThreshold)) > 0 {
			return DirectionRaisesRisk
		}
		if len(approvalpolicy.Signals(after, before, approvalpolicy.PlatformEPSSThreshold)) > 0 {
			return DirectionLowersRisk
		}
		return DirectionAdditive
	case KindVerdict:
		var p VerdictPayload
		if json.Unmarshal(payload, &p) != nil {
			return DirectionLowersRisk
		}
		if p.Verdict == VerdictTruePositive || p.Verdict == VerdictNeedsInfo {
			return DirectionAdditive
		}
		return DirectionLowersRisk
	case KindRemediationSteps, KindSummary:
		return DirectionAdditive
	}
	return DirectionLowersRisk
}

// AutoAction is what the platform does with a new suggestion on its own.
type AutoAction string

const (
	// AutoKeepOpen: wait for a person.
	AutoKeepOpen AutoAction = "keep_open"
	// AutoApply: apply now as the system, undo available.
	AutoApply AutoAction = "apply"
	// AutoRequestApproval: open an approval request as the AI actor; the
	// finding does not change until a person approves.
	AutoRequestApproval AutoAction = "request_approval"
)

// DecideAuto is the fixed apply rule:
//
//   - only auto_apply mode acts on its own;
//   - a suggestion with review reasons (no or unresolved evidence, injection
//     markers, unknown placeholders) is never acted on;
//   - below the minimum confidence nothing is acted on;
//   - additive changes are applied;
//   - lowering risk becomes an approval request, never a change;
//   - severity and priority changes, even upward, wait for a person: the
//     platform applies no severity or priority change without one.
func DecideAuto(mode Mode, minConfidence float64, s *Suggestion) AutoAction {
	if mode != ModeAutoApply || len(s.ReviewReasons) > 0 {
		return AutoKeepOpen
	}
	if s.Confidence == nil || *s.Confidence < minConfidence {
		return AutoKeepOpen
	}
	switch s.Direction {
	case DirectionAdditive:
		if s.Kind == KindSeverity {
			return AutoKeepOpen
		}
		return AutoApply
	case DirectionLowersRisk:
		if s.Kind == KindVerdict {
			return AutoRequestApproval
		}
		return AutoKeepOpen
	}
	return AutoKeepOpen
}
