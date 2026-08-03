package validation

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Detection correlation — CTEM Stage-4's second question.
//
// A validation run answers "is the exposure still reachable?" via
// Outcome. It says NOTHING about whether the defensive stack noticed.
// DetectionStatus answers that second question by correlating the
// tenant's runtime telemetry against the window in which the
// validation actually ran.
//
// ---------------------------------------------------------------
// Why a separate vocabulary from Outcome
// ---------------------------------------------------------------
// Outcome's words 'detected' / 'not_detected' describe the TARGET:
// 'detected' means the probe still reached it (bad news). A detection
// verdict describes our SENSORS: seeing the probe is good news. Same
// words, opposite subject AND opposite polarity. Overloading them
// would make every stored row ambiguous about which question it
// answers, and no amount of documentation fixes an ambiguous datum.
// The two enums below and in Outcome share no member.
//
// ---------------------------------------------------------------
// Why absence of telemetry is not a failure
// ---------------------------------------------------------------
// The single most dangerous thing this feature could do is report
// "nothing detected your attack" when the truth is "no telemetry
// source is connected to this platform". The first is a security
// finding; the second is a configuration gap. They are reported as
// DIFFERENT statuses (DetectionNotObserved vs
// DetectionNoTelemetrySource) and the correlator establishes pipeline
// liveness BEFORE it is willing to say anything negative about a
// control.

// DetectionStatus is the verdict on whether anything observed a
// validation. Deliberately disjoint from Outcome — see file header.
type DetectionStatus string

const (
	// DetectionObserved: telemetry correlated to this validation
	// arrived. Something in the stack saw it.
	DetectionObserved DetectionStatus = "observed"

	// DetectionNotObserved: the tenant IS shipping telemetry, but none
	// of it correlated to this validation. This is the only value that
	// asserts a real detection gap.
	DetectionNotObserved DetectionStatus = "not_observed"

	// DetectionNoTelemetrySource: no telemetry is reaching the platform
	// for this tenant at all. The honest reading is UNKNOWN — we did
	// not look at a control, so we cannot grade one.
	DetectionNoTelemetrySource DetectionStatus = "no_telemetry_source"

	// DetectionNotApplicable: the validation did not execute (error or
	// skipped), so there was no attack to detect. Grading detection
	// here would punish a control for our own failure to run.
	DetectionNotApplicable DetectionStatus = "not_applicable"

	// DetectionNotEvaluated: correlation did not run for this record
	// (probe unwired, or the row predates this feature). Never means
	// "no detection".
	DetectionNotEvaluated DetectionStatus = "not_evaluated"
)

// IsDetectionGap reports whether the status asserts a genuine control
// failure. Only DetectionNotObserved qualifies. Dashboards MUST use
// this rather than `!= observed`, or "no telemetry configured" gets
// rendered as "controls failed" — the exact misreport this feature
// exists to prevent.
func (d DetectionStatus) IsDetectionGap() bool { return d == DetectionNotObserved }

// IsConclusive reports whether the verdict is based on an actual look
// at telemetry. no_telemetry_source / not_applicable / not_evaluated
// are all "we did not or could not look".
func (d DetectionStatus) IsConclusive() bool {
	return d == DetectionObserved || d == DetectionNotObserved
}

// ValidDetectionStatus mirrors the DB CHECK constraint.
func ValidDetectionStatus(d DetectionStatus) bool {
	switch d {
	case DetectionObserved, DetectionNotObserved, DetectionNoTelemetrySource,
		DetectionNotApplicable, DetectionNotEvaluated:
		return true
	}
	return false
}

// Correlation window.
//
// postWindow — how long AFTER the probe ends we keep accepting
// telemetry as caused by it. 5 minutes: EDR/XDR agents batch and
// forward on a timer (CrowdStrike/Defender/osquery forwarders are
// typically seconds to ~2 min; SIEM relay adds more), so anything
// shorter turns normal pipeline latency into fabricated detection
// gaps. Longer buys little: a sensor that takes >5 min is not
// providing actionable detection anyway.
//
// preGrace — how long BEFORE the recorded start we accept. Small (30s)
// and exists only to absorb clock skew between the agent host and the
// API, plus the gap between the command being issued and the probe
// firing.
//
// Failure modes, stated plainly:
//   - FALSE NEGATIVE (reported not_observed though a control did fire):
//     telemetry that arrives later than postWindow, e.g. an hourly
//     batch forwarder. Mitigated by correlation_id, which is
//     time-independent — a stamped event matches whenever it lands,
//     as long as it lands before this evaluation runs.
//   - FALSE POSITIVE (reported observed though nothing detected us):
//     unrelated telemetry on the same asset inside the window. This is
//     the real risk of time-based matching on a busy host. Mitigated
//     two ways: (a) heuristic matching is restricted to event types a
//     network probe could plausibly cause, and (b) every verdict
//     records its match_mode, so an "observed" reached heuristically
//     is auditable and never silently equated with an exact match.
const (
	DetectionPostWindow = 5 * time.Minute
	DetectionPreGrace   = 30 * time.Second

	// telemetryLivenessLookback — how far back we look to decide the
	// pipeline is alive. 24h tolerates a quiet night on a small estate
	// without declaring the pipeline dead.
	telemetryLivenessLookback = 24 * time.Hour
)

// heuristicEventTypes are the runtime_telemetry_events types a remote
// network safe-check could plausibly produce on the target. Restricting
// the time-window fallback to these keeps unrelated host noise
// (file_write, process_stop, kernel_module_load...) from being read as
// a detection. Exact correlation_id matching is NOT restricted.
var heuristicEventTypes = []string{"network_connect", "auth_attempt"}

// TelemetryProbe is the read side of the telemetry stream that the
// correlator needs. Implemented by postgres; faked in tests.
type TelemetryProbe interface {
	// PipelineLive reports whether ANY telemetry (of any kind) has
	// arrived for the tenant since `since`. This is the guard that
	// separates "no detection" from "no telemetry pipeline".
	PipelineLive(ctx context.Context, tenantID shared.ID, since time.Time) (bool, error)

	// CountByCorrelationID counts events a producer explicitly stamped
	// with this validation's correlation id. Exact; no time bounds.
	CountByCorrelationID(ctx context.Context, tenantID, correlationID shared.ID) (int, error)

	// CountNearTarget counts events on the given asset between from and
	// to whose event_type is in eventTypes. The heuristic fallback for
	// producers that cannot stamp a correlation id.
	CountNearTarget(ctx context.Context, tenantID, assetID shared.ID, from, to time.Time, eventTypes []string) (int, error)
}

// DetectionCorrelator turns a completed validation plus the telemetry
// stream into a DetectionStatus. Safe to construct with a nil probe —
// it then reports DetectionNotEvaluated rather than guessing.
type DetectionCorrelator struct {
	probe TelemetryProbe
	now   func() time.Time
}

// NewDetectionCorrelator wires the correlator. probe may be nil, in
// which case every verdict is DetectionNotEvaluated.
func NewDetectionCorrelator(probe TelemetryProbe) *DetectionCorrelator {
	return &DetectionCorrelator{probe: probe, now: func() time.Time { return time.Now().UTC() }}
}

// DetectionVerdict is the correlator's output: the status plus enough
// detail for an operator to audit how it was reached.
type DetectionVerdict struct {
	Status DetectionStatus
	Detail map[string]any
}

// Evaluate decides whether anything observed the validation described
// by ev. correlationID may be zero (no producer stamped anything).
//
// Order of checks is deliberate and is the safety property of this
// function: we refuse to say "not_observed" until we have positively
// established that telemetry is flowing for this tenant. Every earlier
// return is a form of "we don't know", never a control indictment.
func (c *DetectionCorrelator) Evaluate(
	ctx context.Context,
	tenantID shared.ID,
	ev Evidence,
	correlationID shared.ID,
) DetectionVerdict {
	detail := map[string]any{}

	// 1. Nothing ran → nothing could be detected.
	if ev.Outcome == OutcomeError || ev.Outcome == OutcomeSkipped {
		detail["reason"] = "validation did not execute (outcome=" + string(ev.Outcome) + ")"
		return DetectionVerdict{Status: DetectionNotApplicable, Detail: detail}
	}

	// 2. Correlation not wired → we did not look. Not a gap.
	if c.probe == nil || tenantID.IsZero() {
		detail["reason"] = "detection correlation not configured"
		return DetectionVerdict{Status: DetectionNotEvaluated, Detail: detail}
	}

	from, to := c.window(ev)
	detail["window_from"] = from.UTC().Format(time.RFC3339)
	detail["window_to"] = to.UTC().Format(time.RFC3339)
	detail["post_window_seconds"] = int(DetectionPostWindow.Seconds())

	// 3. Exact correlation first — time-independent and unambiguous.
	// Checked BEFORE pipeline liveness: a stamped match is proof the
	// pipeline is alive, and the liveness lookback could otherwise
	// discard a match that arrived outside it.
	if !correlationID.IsZero() {
		detail["correlation_id"] = correlationID.String()
		n, err := c.probe.CountByCorrelationID(ctx, tenantID, correlationID)
		if err != nil {
			detail["reason"] = "correlation lookup failed: " + err.Error()
			return DetectionVerdict{Status: DetectionNotEvaluated, Detail: detail}
		}
		if n > 0 {
			detail["match_mode"] = "correlation_id"
			detail["matched_events"] = n
			detail["confidence"] = "exact"
			return DetectionVerdict{Status: DetectionObserved, Detail: detail}
		}
	}

	// 4. Is telemetry reaching us at all? This is the load-bearing
	// check. Without it, a tenant that has never connected an EDR
	// would see every validation reported as an undetected attack.
	live, err := c.probe.PipelineLive(ctx, tenantID, c.now().Add(-telemetryLivenessLookback))
	if err != nil {
		detail["reason"] = "telemetry pipeline check failed: " + err.Error()
		return DetectionVerdict{Status: DetectionNotEvaluated, Detail: detail}
	}
	detail["telemetry_pipeline_live"] = live
	if !live {
		detail["liveness_lookback_hours"] = int(telemetryLivenessLookback.Hours())
		detail["reason"] = "no runtime telemetry received for this tenant in the lookback window — " +
			"detection cannot be assessed. This is a missing telemetry integration, NOT a failed control."
		return DetectionVerdict{Status: DetectionNoTelemetrySource, Detail: detail}
	}

	// 5. Heuristic fallback: plausible event types on the target asset
	// inside the window.
	if !ev.Target.AssetID.IsZero() {
		detail["target_asset_id"] = ev.Target.AssetID.String()
		detail["heuristic_event_types"] = heuristicEventTypes
		n, herr := c.probe.CountNearTarget(ctx, tenantID, ev.Target.AssetID, from, to, heuristicEventTypes)
		if herr != nil {
			detail["reason"] = "telemetry window query failed: " + herr.Error()
			return DetectionVerdict{Status: DetectionNotEvaluated, Detail: detail}
		}
		if n > 0 {
			detail["match_mode"] = "heuristic_asset_window"
			detail["matched_events"] = n
			detail["confidence"] = "heuristic"
			detail["caveat"] = "matched by asset + time window, not by correlation id; " +
				"unrelated activity on this asset inside the window can produce a false positive"
			return DetectionVerdict{Status: DetectionObserved, Detail: detail}
		}
		detail["matched_events"] = 0
		detail["reason"] = "telemetry is flowing for this tenant but none correlated to this validation"
		return DetectionVerdict{Status: DetectionNotObserved, Detail: detail}
	}

	// 6. Pipeline is live but we have no asset to scope the window to,
	// and nothing was stamped. Asserting a gap here would be guessing.
	detail["reason"] = "validation target has no asset id; cannot scope a telemetry window"
	return DetectionVerdict{Status: DetectionNotEvaluated, Detail: detail}
}

// window returns the correlation bounds for the evidence. Falls back to
// the evaluation time when the executor did not report timestamps.
func (c *DetectionCorrelator) window(ev Evidence) (time.Time, time.Time) {
	start := ev.StartedAt
	end := ev.EndedAt
	if start.IsZero() {
		start = c.now()
	}
	if end.IsZero() || end.Before(start) {
		end = start
	}
	return start.Add(-DetectionPreGrace), end.Add(DetectionPostWindow)
}
