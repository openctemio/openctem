// Package retest is the domain of continuous retest (RFC-039,
// docs/rfcs/RFC-039-continuous-retest.md): re-running the exact check that
// produced a finding, deciding whether it is fixed, still present or unknown,
// and what that means for the finding's status.
//
// The two decisions are pure functions (Decide, NextStatus) so the rules are
// testable without a sensor or a database.
package retest

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Trigger says who started a retest.
type Trigger string

const (
	// TriggerManual is "Retest now" by a user.
	TriggerManual Trigger = "manual"
	// TriggerAuto is the auto-retest scheduler.
	TriggerAuto Trigger = "auto"
)

// Status is the lifecycle of one retest attempt.
type Status string

const (
	StatusPending   Status = "pending"
	StatusCompleted Status = "completed"
)

// Outcome is what a completed retest concluded.
type Outcome string

const (
	// OutcomeFixed: the template no longer matched AND the target answered.
	OutcomeFixed Outcome = "fixed"
	// OutcomeStillPresent: the template matched again.
	OutcomeStillPresent Outcome = "still_present"
	// OutcomeUnknown: no conclusion — the target did not answer, the template
	// is not installed on the sensor, the run failed or no result came back.
	// A finding is never moved on unknown.
	OutcomeUnknown Outcome = "unknown"
)

// ActorName is the audit actor of every status change a retest makes.
const ActorName = "system: retest"

// ResolutionMethodRetestVerified is the resolution_method a retest stamps when
// it resolves a finding.
const ResolutionMethodRetestVerified = vulnerability.ResolutionMethodRetestVerified

// Sentinel errors. They wrap the shared kinds so the HTTP layer maps them.
var (
	// ErrNotEligible: the finding has no deterministic re-check (not a nuclei
	// finding, a disposition status, a non-addressable or out-of-scope asset).
	ErrNotEligible = fmt.Errorf("%w: finding is not eligible for retest", shared.ErrValidation)
	// ErrInFlight: a retest of this finding is already pending.
	ErrInFlight = fmt.Errorf("%w: a retest of this finding is already in progress", shared.ErrConflict)
	// ErrRateLimited: a per-finding cooldown or an in-flight cap was hit.
	ErrRateLimited = errors.New("retest rate limit")
	// ErrNoSensor: no sensor that can re-run a nuclei template is online.
	ErrNoSensor = fmt.Errorf("%w: no sensor that can re-run nuclei templates is online for this tenant", shared.ErrValidation)
)

// Retest is one retest attempt of one finding.
type Retest struct {
	ID             shared.ID
	TenantID       shared.ID
	FindingID      shared.ID
	AssetID        shared.ID
	Trigger        Trigger
	RequestedBy    *shared.ID
	Status         Status
	Outcome        Outcome
	Reason         string
	PriorStatus    vulnerability.FindingStatus
	ResultStatus   vulnerability.FindingStatus
	TemplateID     string
	Target         string
	CheckCommandID *shared.ID
	ReachCommandID *shared.ID
	DeadlineAt     time.Time
	CreatedAt      time.Time
	CompletedAt    *time.Time
}

// CheckResult is what one of a retest's two commands reported. Outcome uses the
// validate command vocabulary: detected / not_detected / inconclusive / error /
// skipped. Missing is true when the command never produced a result (failed,
// expired, canceled, or the retest deadline passed first).
type CheckResult struct {
	Outcome string
	Summary string
	Missing bool
}

const (
	checkDetected    = "detected"
	checkNotDetected = "not_detected"
)

// Decide combines the template re-run (check) and the reachability probe
// (reach) into a retest outcome and a human reason.
//
// The reachability probe is the guard against the false "fixed" a down host
// produces: nuclei prints nothing and exits 0 when the target does not answer,
// which the sensor reports as not_detected. "No match" only counts as fixed
// when the same target was reachable.
func Decide(check, reach CheckResult) (Outcome, string) {
	if check.Missing {
		return OutcomeUnknown, "no result from the template re-run"
	}
	switch check.Outcome {
	case checkDetected:
		return OutcomeStillPresent, nonEmpty(check.Summary, "the detection template matched again")
	case checkNotDetected:
		if reach.Missing {
			return OutcomeUnknown, "template did not match, but the reachability probe returned no result"
		}
		if reach.Outcome == checkDetected {
			return OutcomeFixed, "template did not match and the target answered"
		}
		return OutcomeUnknown, "target unreachable: " + nonEmpty(reach.Summary, "the reachability probe did not connect")
	default:
		return OutcomeUnknown, nonEmpty(check.Summary, "the template re-run was inconclusive")
	}
}

// eligibleStatuses are the statuses a retest may run on and move. Deliberate
// dispositions (false positive, accepted risk, duplicate) and the pentest
// workflow are never retested.
var eligibleStatuses = map[vulnerability.FindingStatus]bool{ //nolint:gochecknoglobals // static rule table
	vulnerability.FindingStatusNew:            true,
	vulnerability.FindingStatusConfirmed:      true,
	vulnerability.FindingStatusInProgress:     true,
	vulnerability.FindingStatusFixApplied:     true,
	vulnerability.FindingStatusValidatedFixed: true,
	vulnerability.FindingStatusResolved:       true,
}

// EligibleStatus reports whether a finding in status s may be retested.
func EligibleStatus(s vulnerability.FindingStatus) bool { return eligibleStatuses[s] }

// EligibleStatuses lists the statuses a retest may run on (for queries).
func EligibleStatuses() []string {
	return []string{
		string(vulnerability.FindingStatusNew), string(vulnerability.FindingStatusConfirmed),
		string(vulnerability.FindingStatusInProgress), string(vulnerability.FindingStatusFixApplied),
		string(vulnerability.FindingStatusValidatedFixed), string(vulnerability.FindingStatusResolved),
	}
}

// NextStatus is the finding status a retest outcome leads to from status prior,
// and whether it changes. Unknown never moves a finding; neither does an
// ineligible status.
//
//	fixed:          open / fix_applied / validated_fixed → resolved; resolved stays
//	still_present:  resolved → confirmed (regression); fix_applied → in_progress;
//	                validated_fixed → confirmed; open stays
func NextStatus(prior vulnerability.FindingStatus, outcome Outcome) (vulnerability.FindingStatus, bool) {
	if !EligibleStatus(prior) {
		return prior, false
	}
	switch outcome {
	case OutcomeFixed:
		if prior == vulnerability.FindingStatusResolved {
			return prior, false
		}
		return vulnerability.FindingStatusResolved, true
	case OutcomeStillPresent:
		switch prior {
		case vulnerability.FindingStatusResolved, vulnerability.FindingStatusValidatedFixed:
			return vulnerability.FindingStatusConfirmed, true
		case vulnerability.FindingStatusFixApplied:
			return vulnerability.FindingStatusInProgress, true
		default:
			return prior, false
		}
	default:
		return prior, false
	}
}

// IsRegression reports whether moving from prior to next reopens a finding that
// had been closed as fixed.
func IsRegression(prior, next vulnerability.FindingStatus) bool {
	return prior == vulnerability.FindingStatusResolved && next.IsOpen()
}

// ResolutionNote is the resolution text a retest stamps on a finding it resolves.
func ResolutionNote(templateID string) string {
	return "retest: not detected (" + templateID + ")"
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

// SettleDecision is what the retest service decides once the finding's current
// status is known under the row lock.
type SettleDecision struct {
	Next   vulnerability.FindingStatus
	Change bool
}

// SettleInput completes one retest.
type SettleInput struct {
	TenantID   shared.ID
	RetestID   shared.ID
	FindingID  shared.ID
	Outcome    Outcome
	Reason     string
	ResolvedBy *shared.ID // stamped when the finding is resolved
	TemplateID string
	// Decide maps the finding's current status to the status the outcome
	// leads to. It runs inside the transaction, with the finding row locked.
	Decide func(current vulnerability.FindingStatus) SettleDecision
	// Activity is the retest_completed entry's changes; the repository adds
	// old_status, new_status and moved.
	Activity map[string]any
	Source   vulnerability.ActivitySource
}

// SettleResult reports what Settle did.
type SettleResult struct {
	Applied      bool // false: the retest was no longer pending (settled elsewhere)
	Moved        bool
	PriorStatus  vulnerability.FindingStatus
	ResultStatus vulnerability.FindingStatus
}

// AutoTenant is a tenant with auto-retest on, as the scheduler lists it.
type AutoTenant struct {
	TenantID      shared.ID
	NextRunAt     *time.Time // nil: never claimed
	IntervalHours int        // 0 = default
	DailyCap      int        // 0 = default
}
