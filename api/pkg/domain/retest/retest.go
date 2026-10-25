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

	"github.com/openctemio/openctem/api/pkg/domain/evidence"
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
	// TriggerProofOfFix is the automatic retest of a finding marked
	// fix_applied (by a person, or by a Jira "Done"). It replaces the retired
	// whole-asset verification scan (RFC-039 D4).
	TriggerProofOfFix Trigger = "proof_of_fix"
)

// IsSystem reports whether the retest was started by the platform, not a user.
func (t Trigger) IsSystem() bool { return t == TriggerAuto || t == TriggerProofOfFix }

// Status is the lifecycle of one retest attempt.
type Status string

const (
	StatusPending   Status = "pending"
	StatusCompleted Status = "completed"
)

// Outcome is what a completed retest concluded (RFC-057 R2). A check that
// did not match is not, by itself, proof of a fix.
type Outcome string

const (
	// OutcomeConfirmedFixed: the re-run requested the finding's own endpoint,
	// an HTTP answer came back that is not a block, an auth failure or a
	// server error, the check evaluated it and did not match, and the
	// template is the one the finding was last seen with.
	OutcomeConfirmedFixed Outcome = "confirmed_fixed"
	// OutcomeNotReproduced: the check did not match, but nothing proves the
	// endpoint was evaluated (no request evidence from the sensor). The
	// finding does not move.
	OutcomeNotReproduced Outcome = "not_reproduced"
	// OutcomeStillVulnerable: the check matched again.
	OutcomeStillVulnerable Outcome = "still_vulnerable"
	// OutcomeInconclusive: no conclusion; ReasonCode says why. The finding
	// does not move.
	OutcomeInconclusive Outcome = "inconclusive"
	// OutcomeStillExposedElsewhere: the check no longer matches the finding's
	// own endpoint (or never requested it) but matches at another path of
	// the same target. Nothing is proven fixed and nothing is reopened: the
	// finding stays as it is, and the other paths are named in the reason.
	OutcomeStillExposedElsewhere Outcome = "still_exposed_elsewhere"
)

// ReasonCode classifies a retest's outcome.
type ReasonCode string

const (
	ReasonMatched         ReasonCode = "matched"
	ReasonNotMatched      ReasonCode = "not_matched"
	ReasonNoEndpointProof ReasonCode = "no_endpoint_proof"
	ReasonUnreachable     ReasonCode = "unreachable"
	ReasonBlocked         ReasonCode = "blocked"
	// ReasonEdgeBlocked: a CDN or WAF answered in place of the service
	// (challenge or block page): nothing is known about the service.
	ReasonEdgeBlocked ReasonCode = "edge_blocked"
	// ReasonAccessDenied: the service itself answered 401 or 403. For an
	// exposure check seen twice that is the fix; otherwise inconclusive.
	ReasonAccessDenied     ReasonCode = "access_denied"
	ReasonAuthChanged      ReasonCode = "auth_changed"
	ReasonServerError      ReasonCode = "server_error"
	ReasonEndpointMismatch ReasonCode = "endpoint_mismatch"
	// ReasonMatchedElsewhere: the check matched at another path than the
	// finding's endpoint.
	ReasonMatchedElsewhere ReasonCode = "matched_elsewhere"
	ReasonTemplateChanged  ReasonCode = "template_changed"
	ReasonNoResult         ReasonCode = "no_result"
	ReasonError            ReasonCode = "error"
	// ReasonTemplateNotFound: the sensor's template set does not hold the
	// finding's template.
	ReasonTemplateNotFound ReasonCode = "template_not_found"
	// ReasonExcludedByPolicy: the template is installed, but the sensor's
	// safety policy never runs it for a re-check (a destructive, intrusive
	// or brute-force class).
	ReasonExcludedByPolicy ReasonCode = "excluded_by_policy"
	// ReasonNoVerdict: the tool ended without judging the item (it stopped
	// early or never reached the target).
	ReasonNoVerdict ReasonCode = "no_verdict"
	// ReasonCheckUncalibrated: a custom retest check did not match, but this
	// version of the check never matched the finding, so the no-match does
	// not prove a fix (docs/architecture/finding-retest-checks.md).
	ReasonCheckUncalibrated ReasonCode = "check_uncalibrated"
)

// ToolUnable reports whether the code says the tool could not run the check
// (a gap of the tool or its template set, not a finding about the target).
func (c ReasonCode) ToolUnable() bool {
	switch c {
	case ReasonError, ReasonTemplateNotFound, ReasonExcludedByPolicy, ReasonNoVerdict:
		return true
	}
	return false
}

// Verdict is a decided outcome with its reason code and a human reason.
type Verdict struct {
	Outcome Outcome
	Code    ReasonCode
	Reason  string
	// OtherPaths are the other URLs the check matched at (display form, a
	// few), set with OutcomeStillExposedElsewhere.
	OtherPaths []string
}

// inconclusive is a Verdict without a conclusion.
func inconclusive(code ReasonCode, reason string) Verdict {
	return Verdict{Outcome: OutcomeInconclusive, Code: code, Reason: reason}
}

// Inconclusive is an inconclusive Verdict (for the service's own failures).
func Inconclusive(code ReasonCode, reason string) Verdict { return inconclusive(code, reason) }

// matchedSomewhere: the outcome says the check matched, at the finding's
// endpoint or at another path.
func (o Outcome) matchedSomewhere() bool {
	return o == OutcomeStillVulnerable || o == OutcomeStillExposedElsewhere
}

// Conclusive reports whether the outcome says something about the finding.
func (o Outcome) Conclusive() bool { return o == OutcomeConfirmedFixed || o == OutcomeStillVulnerable }

// ActorName is the audit actor of every status change a retest makes.
const ActorName = "system: retest"

// Sentinel errors. They wrap the shared kinds so the HTTP layer maps them.
var (
	// ErrNotEligible: the finding has no deterministic re-check (no tool rule
	// to re-run, a disposition status, a non-addressable or out-of-scope asset).
	ErrNotEligible = fmt.Errorf("%w: finding is not eligible for retest", shared.ErrValidation)
	// ErrInFlight: a retest of this finding is already pending.
	ErrInFlight = fmt.Errorf("%w: a retest of this finding is already in progress", shared.ErrConflict)
	// ErrRateLimited: a per-finding cooldown or an in-flight cap was hit.
	ErrRateLimited = errors.New("retest rate limit")
	// ErrNoSensor: no sensor that can re-check the finding is online (no
	// retest handler for its tool, nor a nuclei validation sensor).
	ErrNoSensor = fmt.Errorf("%w: no sensor that can retest this finding is online for this tenant", shared.ErrValidation)
	// ErrNoCheckSensor: the finding has a custom retest check, and no online
	// sensor of the tenant can run delivered templates in a retest.
	ErrNoCheckSensor = fmt.Errorf("%w: no online sensor of this organization can run custom retest checks (a sensor update adds it)", shared.ErrValidation)
)

// Retest is one retest attempt of one finding.
type Retest struct {
	ID           shared.ID
	TenantID     shared.ID
	FindingID    shared.ID
	AssetID      shared.ID
	Trigger      Trigger
	RequestedBy  *shared.ID
	Status       Status
	Outcome      Outcome
	ReasonCode   ReasonCode
	Reason       string
	PriorStatus  vulnerability.FindingStatus
	ResultStatus vulnerability.FindingStatus
	// TemplateID is the rule re-run: the nuclei template id, or the
	// finding's rule id for a tool retest.
	TemplateID string
	Target     string
	// Method is how the retest re-checks (MethodTool, MethodValidate). Not
	// stored: it follows from the check command's type.
	Method         string
	CheckCommandID *shared.ID
	ReachCommandID *shared.ID
	// RunID is the scan run (kind retest) that holds the commands, their
	// logs and the outcome, so the retest shows up in Runs.
	RunID *shared.ID
	// SensorID is the sensor that ran the check (set when the retest settles).
	SensorID *shared.ID
	// CheckID, CheckDigest and CheckPath are set when the retest ran the
	// finding's custom retest check: which check, the exact content digest
	// sent, and the path on the target it had to prove it requested.
	CheckID     *shared.ID
	CheckDigest string
	CheckPath   string
	DeadlineAt  time.Time
	CreatedAt   time.Time
	CompletedAt *time.Time
}

// CheckResult is what one of a retest's two commands reported. Outcome uses the
// validate command vocabulary: detected / not_detected / inconclusive / error /
// skipped. Missing is true when the command never produced a result (failed,
// expired, canceled, or the retest deadline passed first).
type CheckResult struct {
	Outcome string
	Summary string
	Missing bool
	// TemplateDigest is the sha256 of the template the re-run used
	// (evidence.template_digest, sensor#134); "" when not reported.
	TemplateDigest string
	// Evidence is what the re-run reported it sent and received
	// (evidence_items in the result), normalized but not masked.
	Evidence []evidence.Item
	// Requests is one line per request the re-run made (newer sensors).
	Requests []RequestResult
}

const (
	checkDetected    = "detected"
	checkNotDetected = "not_detected"
)

// Decide combines the template re-run (check) and the reachability probe
// (reach) into a verdict. matchedAt is the finding's recorded endpoint.
//
// A non-match counts as confirmed fixed only when the re-run's own evidence
// proves it requested that endpoint and got an answer that is not a block,
// an auth failure or a server error. Without request evidence a non-match on
// a reachable target is "not reproduced" (nothing moves); without a reachable
// target it is inconclusive. nuclei prints nothing and exits 0 when a host
// does not answer, and a template run with the wrong input never requests the
// endpoint, so a bare "not detected" proves nothing.
func Decide(check, reach CheckResult, matchedAt string, cls ...Class) Verdict {
	if check.Missing {
		return inconclusive(ReasonNoResult, "no result from the template re-run")
	}
	switch check.Outcome {
	case checkDetected, checkNotDetected:
		// A check that probes several paths reports each request: the
		// finding's own endpoint decides, not whichever exchange came first.
		if v, ok := DecideByRequests(check.Requests, matchedAt, firstClass(cls)); ok {
			return v
		}
	}
	switch check.Outcome {
	case checkDetected:
		return Verdict{Outcome: OutcomeStillVulnerable, Code: ReasonMatched,
			Reason: nonEmpty(evidence.RedactText(check.Summary), "the detection template matched again")}
	case checkNotDetected:
		reached := !reach.Missing && reach.Outcome == checkDetected
		detail := "the reachability probe returned no result"
		if !reach.Missing {
			detail = nonEmpty(evidence.RedactText(reach.Summary), "the reachability probe did not connect")
		}
		return decideNotMatched(AnalyzeAttempt(check.Evidence, matchedAt), matchedAt, reached, detail, firstClass(cls))
	default:
		return inconclusive(ReasonError, nonEmpty(evidence.RedactText(check.Summary), "the template re-run was inconclusive"))
	}
}

// ApplyTemplateDrift turns a conclusive verdict inconclusive when the
// template content changed since the finding's last sighting (research/18
// O6): baseline is the template digest recorded at that sighting, digest the
// re-run's. A tightened matcher reads as fixed, a widened one as still
// present. Without a baseline (sighted before provenance existed, or by
// another tool) the verdict stands. requireDigest says whether a re-run that
// reported no digest counts as drift: always for a fix; for a match only on
// the validate path (a tool verdict reports a digest only from newer sensors).
func ApplyTemplateDrift(v Verdict, baseline, digest string, requireDigest bool) Verdict {
	if baseline == "" || !v.Outcome.Conclusive() {
		return v
	}
	switch {
	case digest == "" && (requireDigest || v.Outcome == OutcomeConfirmedFixed):
		return inconclusive(ReasonTemplateChanged, "the re-run reported no template digest, so it cannot be tied to the template recorded at the last sighting ("+shortDigest(baseline)+"); a new scan sighting re-baselines it")
	case digest != "" && digest != baseline:
		return inconclusive(ReasonTemplateChanged, "the template changed since the last sighting (recorded "+shortDigest(baseline)+", re-run "+shortDigest(digest)+"); a new scan sighting re-baselines it")
	}
	return v
}

// ApplyCheckCalibration decides what a custom retest check's verdict proves
// (docs/architecture/finding-retest-checks.md). sent is the digest of the
// check the platform sent, reported the digest the sensor says it ran,
// calibrated the digest that matched the finding once ("" when none).
//
//   - a conclusive verdict about other content than was sent is
//     inconclusive (template_changed);
//   - a match is still vulnerable (and calibrates the check, the caller's
//     job);
//   - a no-match proves a fix only when this exact version matched the
//     finding before; otherwise it is not reproduced (check_uncalibrated),
//     so a check that can never match cannot close a finding.
func ApplyCheckCalibration(v Verdict, sent, reported, calibrated string) Verdict {
	if !v.Outcome.Conclusive() {
		return v
	}
	if sent == "" || reported != sent {
		return inconclusive(ReasonTemplateChanged, "the sensor did not report running the retest check that was sent ("+
			shortDigest(sent)+"); the attempt cannot count")
	}
	if v.Outcome == OutcomeConfirmedFixed && calibrated != sent {
		return Verdict{Outcome: OutcomeNotReproduced, Code: ReasonCheckUncalibrated,
			Reason: "the retest check did not match, but this version of it has never matched the finding, so the no-match does not prove a fix; " +
				"a check proves a fix only after it reproduced the issue once"}
	}
	return v
}

// shortDigest is "sha256:" and the first 12 hex digits of d.
func shortDigest(d string) string {
	if len(d) > len("sha256:")+12 {
		return d[:len("sha256:")+12]
	}
	return d
}

// eligibleStatuses are the statuses a retest may run on and move. Deliberate
// dispositions (false positive, accepted risk, duplicate) and the pentest
// workflow are never retested.
var eligibleStatuses = map[vulnerability.FindingStatus]bool{ //nolint:gochecknoglobals // static rule table
	vulnerability.FindingStatusNew:        true,
	vulnerability.FindingStatusConfirmed:  true,
	vulnerability.FindingStatusInProgress: true,
	vulnerability.FindingStatusFixApplied: true,
	vulnerability.FindingStatusResolved:   true,
}

// EligibleStatus reports whether a finding in status s may be retested.
func EligibleStatus(s vulnerability.FindingStatus) bool { return eligibleStatuses[s] }

// EligibleStatuses lists the statuses a retest may run on (for queries).
func EligibleStatuses() []string {
	return []string{
		string(vulnerability.FindingStatusNew), string(vulnerability.FindingStatusConfirmed),
		string(vulnerability.FindingStatusInProgress), string(vulnerability.FindingStatusFixApplied),
		string(vulnerability.FindingStatusResolved),
	}
}

// NextStatus is the finding status a retest outcome leads to from status
// prior, and whether it changes. Only a conclusive outcome moves a finding,
// and never one in an ineligible status.
//
//	confirmed_fixed:  resolved stays; with autoResolve the rest → resolved;
//	                  otherwise the status stays and the finding's validation
//	                  says not_reproducible (ValidationOutcome): a person closes it
//	still_vulnerable: resolved → confirmed (regression); fix_applied → in_progress;
//	                  open stays (validation: reproducible)
func NextStatus(prior vulnerability.FindingStatus, outcome Outcome, autoResolve bool) (vulnerability.FindingStatus, bool) {
	if !EligibleStatus(prior) {
		return prior, false
	}
	switch outcome {
	case OutcomeConfirmedFixed:
		switch {
		case prior == vulnerability.FindingStatusResolved:
			return prior, false
		case autoResolve:
			return vulnerability.FindingStatusResolved, true
		default:
			return prior, false
		}
	case OutcomeStillVulnerable:
		switch prior {
		case vulnerability.FindingStatusResolved:
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

// ValidationOutcome is the findings.validation_outcome a conclusive retest
// outcome stamps on an eligible finding ("" for an inconclusive one):
// confirmed_fixed is not_reproducible, still_vulnerable is reproducible.
func ValidationOutcome(o Outcome) string {
	switch o {
	case OutcomeConfirmedFixed:
		return "not_reproducible"
	case OutcomeStillVulnerable:
		return "reproducible"
	default:
		return ""
	}
}

// IsRegression reports whether moving from prior to next reopens a finding that
// had been closed as fixed.
func IsRegression(prior, next vulnerability.FindingStatus) bool {
	return prior == vulnerability.FindingStatusResolved && next.IsOpen()
}

// ResolutionNote is the resolution text a retest stamps on a finding it resolves.
func ResolutionNote(templateID string) string {
	return "retest: confirmed fixed (" + templateID + ")"
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
	ReasonCode ReasonCode
	Reason     string
	// SensorID is the sensor that ran the check; nil when none claimed it.
	SensorID   *shared.ID
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
