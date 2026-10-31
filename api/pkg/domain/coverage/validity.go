package coverage

// Observation validity of a failed pair (docs/rfcs/RFC-093-asset-coverage.md,
// "Platform-side failures"): a failure counts against the target only when
// it is an observation of the target, made over a path that worked. Every
// other failure is the platform's or the sensor's: the check did not run, so
// it says nothing about the target. It never grows the target's fail streak,
// never raises the organization's "keeps failing" alert and is an operator
// signal instead (metric and the platform administrators' alert channel).
//
// The rule fails closed: an outcome this package does not know is platform
// side, never a fact about the target.

import (
	"context"
	"slices"

	"github.com/openctemio/ctis/outcome"
)

// observedOutcomes are the failure outcomes that are observations of the
// target or of what stands in front of it, besides the target-side ones
// (TargetSideOutcomes): an edge protection answered in place of the service,
// or the target pushed back. The organization owns them (an allowlist, a
// rate limit), and they count toward its fail streak.
var observedOutcomes = []string{
	string(outcome.EdgeBlocked), string(outcome.EdgeChallenged), string(outcome.RateLimited),
}

// platformSideOutcomes is the closed list of known platform-side failure
// outcomes: no task carried the target, the run never finished, the task
// failed as a whole (or every target of it failed the same way, which points
// at the sensor), the tool broke, the sensor's own egress refused the
// target, its network or proxy failed, or the run did not finish the target.
// It names the metric label; IsPlatformSide does not depend on it (any
// outcome that is not an observation is platform side).
var platformSideOutcomes = []string{
	OutcomeNotDispatched, OutcomeStalled, OutcomeFailed, OutcomeUnfinished,
	string(outcome.ToolError), string(outcome.EgressRefused), string(outcome.SensorNetworkFault),
}

// PlatformOutcomeOther is the metric label of a platform-side outcome that
// is not in the known list.
const PlatformOutcomeOther = "other"

// IsPlatformSide reports whether a failure outcome is the platform's or the
// sensor's rather than an observation of the target: anything that is
// neither target side (unreachable, timeout) nor an edge or rate-limit
// answer. Unknown outcomes are platform side (fail closed).
func IsPlatformSide(o string) bool {
	return !IsTargetSide(o) && !slices.Contains(observedOutcomes, o)
}

// ObservedFailureOutcomes returns the failure outcomes that count against
// the target: target side and edge or rate-limit answers. The organization's
// "keeps failing" count reads only pairs whose last outcome is one of them.
func ObservedFailureOutcomes() []string {
	return append(TargetSideOutcomes(), observedOutcomes...)
}

// PlatformOutcomeLabel is the bounded metric label of a platform-side
// outcome: the outcome when it is in the known list, else
// PlatformOutcomeOther (a sensor-chosen string never becomes a label).
func PlatformOutcomeLabel(o string) string {
	if slices.Contains(platformSideOutcomes, o) {
		return o
	}
	return PlatformOutcomeOther
}

// PlatformSideOutcomes returns the known platform-side outcomes.
func PlatformSideOutcomes() []string { return slices.Clone(platformSideOutcomes) }

// PlatformFailingStreak is the number of platform-side failures in a row
// after which a pair counts in the operator's platform failure count.
const PlatformFailingStreak = FailingStreak

// PlatformFailureCount is one fleet-wide aggregate of pairs failing on the
// platform side: counts only, never a tenant, an asset or a target.
type PlatformFailureCount struct {
	Capability string
	// Outcome is PlatformOutcomeLabel of the pairs' last outcome.
	Outcome string
	Pairs   int
	// Tenants is how many organizations the pairs belong to.
	Tenants int
}

// PlatformFailureReader reads the fleet-wide platform-side failures: the
// operator's signal, read across organizations on purpose and returned as
// counts only.
type PlatformFailureReader interface {
	// PlatformFailures returns, per capability and outcome, the failed
	// pairs with at least PlatformFailingStreak platform-side failures in
	// a row.
	PlatformFailures(ctx context.Context) ([]PlatformFailureCount, error)
}
