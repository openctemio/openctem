package validation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// fakeProbe is a scriptable TelemetryProbe that records what it was asked.
type fakeProbe struct {
	live     bool
	liveErr  error
	byCorrID map[string]int
	corrErr  error
	nearN    int
	nearErr  error

	// captured arguments
	gotSince      time.Time
	gotFrom       time.Time
	gotTo         time.Time
	gotTypes      []string
	nearCalls     int
	livenessCalls int
}

func (f *fakeProbe) PipelineLive(_ context.Context, _ shared.ID, since time.Time) (bool, error) {
	f.livenessCalls++
	f.gotSince = since
	return f.live, f.liveErr
}

func (f *fakeProbe) CountByCorrelationID(_ context.Context, _ shared.ID, correlationID shared.ID) (int, error) {
	if f.corrErr != nil {
		return 0, f.corrErr
	}
	return f.byCorrID[correlationID.String()], nil
}

func (f *fakeProbe) CountNearTarget(
	_ context.Context, _ shared.ID, _ shared.ID, from, to time.Time, eventTypes []string,
) (int, error) {
	f.nearCalls++
	f.gotFrom, f.gotTo, f.gotTypes = from, to, eventTypes
	return f.nearN, f.nearErr
}

func baseEvidence() Evidence {
	start := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	return Evidence{
		ExecutorKind: "safe-check",
		Outcome:      OutcomeDetected, // exposure still reachable
		StartedAt:    start,
		EndedAt:      start.Add(10 * time.Second),
		Target:       Target{AssetID: shared.NewID(), Type: "host", Address: "example.com:443"},
	}
}

// ---------------------------------------------------------------
// The vocabulary invariant — the single most important property.
// ---------------------------------------------------------------

// TestDetectionStatusDisjointFromOutcome is the guard on the central
// design decision: the detection verdict must never be expressible in
// the same words as the reachability outcome. `outcome='detected'`
// means the exposure is still reachable (bad); a detection verdict of
// "we saw it" is good. If a future change adds "detected" to
// DetectionStatus (or "observed" to Outcome), stored rows become
// ambiguous about which question they answer — and this test fails.
func TestDetectionStatusDisjointFromOutcome(t *testing.T) {
	outcomes := []Outcome{
		OutcomeDetected, OutcomeNotDetected, OutcomeInconclusive, OutcomeError, OutcomeSkipped,
	}
	statuses := []DetectionStatus{
		DetectionObserved, DetectionNotObserved, DetectionNoTelemetrySource,
		DetectionNotApplicable, DetectionNotEvaluated,
	}
	for _, o := range outcomes {
		for _, d := range statuses {
			if string(o) == string(d) {
				t.Fatalf("vocabulary collision: Outcome %q and DetectionStatus %q share a value; "+
					"a stored row can no longer say which question it answers", o, d)
			}
		}
	}
}

// ---------------------------------------------------------------
// The case that will be wrong in the field.
// ---------------------------------------------------------------

// TestNoTelemetryPipelineIsNotADetectionGap is the test the whole
// feature turns on. Today NO first-party producer writes
// runtime_telemetry_events, so this is the state every real tenant is
// in. Reporting it as "not_observed" would tell an operator their
// controls failed to catch an attack when the truth is that no
// telemetry source is connected at all.
func TestNoTelemetryPipelineIsNotADetectionGap(t *testing.T) {
	probe := &fakeProbe{live: false} // nothing has ever arrived
	c := NewDetectionCorrelator(probe)

	v := c.Evaluate(context.Background(), shared.NewID(), baseEvidence(), shared.ID{})

	if v.Status != DetectionNoTelemetrySource {
		t.Fatalf("status = %q, want %q", v.Status, DetectionNoTelemetrySource)
	}
	if v.Status.IsDetectionGap() {
		t.Fatal("no_telemetry_source must NOT count as a detection gap — " +
			"it is a missing integration, not a failed control")
	}
	if v.Status.IsConclusive() {
		t.Fatal("no_telemetry_source must not be reported as a conclusive verdict")
	}
	// The verdict must carry the reason, or an operator sees a bare
	// status and assumes the worst.
	if v.Detail["reason"] == nil {
		t.Fatal("verdict must explain why detection could not be assessed")
	}
	if live, ok := v.Detail["telemetry_pipeline_live"].(bool); !ok || live {
		t.Fatalf("detail must record pipeline liveness=false, got %v", v.Detail["telemetry_pipeline_live"])
	}
	// We must never have looked at the asset window: with no pipeline
	// there is nothing to look at, and querying would imply we did.
	if probe.nearCalls != 0 {
		t.Fatalf("must not query the telemetry window when the pipeline is dead (calls=%d)", probe.nearCalls)
	}
}

// TestPipelineLiveButNothingCorrelated is the ONLY path allowed to
// assert a real control gap.
func TestPipelineLiveButNothingCorrelated(t *testing.T) {
	probe := &fakeProbe{live: true, nearN: 0}
	c := NewDetectionCorrelator(probe)

	v := c.Evaluate(context.Background(), shared.NewID(), baseEvidence(), shared.ID{})

	if v.Status != DetectionNotObserved {
		t.Fatalf("status = %q, want %q", v.Status, DetectionNotObserved)
	}
	if !v.Status.IsDetectionGap() {
		t.Fatal("not_observed is the one status that should count as a detection gap")
	}
	if !v.Status.IsConclusive() {
		t.Fatal("not_observed is based on a real look at telemetry; it is conclusive")
	}
}

// ---------------------------------------------------------------
// Matching
// ---------------------------------------------------------------

func TestObservedViaCorrelationID(t *testing.T) {
	corrID := shared.NewID()
	// Pipeline reports NOT live, to prove the exact-match path does not
	// depend on the liveness lookback: a stamped event is proof enough.
	probe := &fakeProbe{live: false, byCorrID: map[string]int{corrID.String(): 3}}
	c := NewDetectionCorrelator(probe)

	v := c.Evaluate(context.Background(), shared.NewID(), baseEvidence(), corrID)

	if v.Status != DetectionObserved {
		t.Fatalf("status = %q, want %q", v.Status, DetectionObserved)
	}
	if v.Detail["match_mode"] != "correlation_id" {
		t.Fatalf("match_mode = %v, want correlation_id", v.Detail["match_mode"])
	}
	if v.Detail["confidence"] != "exact" {
		t.Fatalf("confidence = %v, want exact", v.Detail["confidence"])
	}
	if v.Detail["matched_events"] != 3 {
		t.Fatalf("matched_events = %v, want 3", v.Detail["matched_events"])
	}
}

func TestObservedViaHeuristicCarriesItsCaveat(t *testing.T) {
	probe := &fakeProbe{live: true, nearN: 1}
	c := NewDetectionCorrelator(probe)

	v := c.Evaluate(context.Background(), shared.NewID(), baseEvidence(), shared.ID{})

	if v.Status != DetectionObserved {
		t.Fatalf("status = %q, want %q", v.Status, DetectionObserved)
	}
	if v.Detail["match_mode"] != "heuristic_asset_window" {
		t.Fatalf("match_mode = %v, want heuristic_asset_window", v.Detail["match_mode"])
	}
	// A heuristic match must never be presented as equivalent to an
	// exact one — unrelated activity on a busy asset can produce it.
	if v.Detail["confidence"] != "heuristic" {
		t.Fatalf("confidence = %v, want heuristic", v.Detail["confidence"])
	}
	if v.Detail["caveat"] == nil {
		t.Fatal("a heuristic match must record its false-positive caveat")
	}
}

// TestHeuristicWindowBounds pins the correlation window actually used.
func TestHeuristicWindowBounds(t *testing.T) {
	probe := &fakeProbe{live: true, nearN: 0}
	c := NewDetectionCorrelator(probe)
	ev := baseEvidence()

	c.Evaluate(context.Background(), shared.NewID(), ev, shared.ID{})

	wantFrom := ev.StartedAt.Add(-DetectionPreGrace)
	wantTo := ev.EndedAt.Add(DetectionPostWindow)
	if !probe.gotFrom.Equal(wantFrom) {
		t.Fatalf("window from = %v, want %v", probe.gotFrom, wantFrom)
	}
	if !probe.gotTo.Equal(wantTo) {
		t.Fatalf("window to = %v, want %v", probe.gotTo, wantTo)
	}
	// The heuristic must not sweep in host noise that a remote network
	// probe could not have caused.
	for _, et := range probe.gotTypes {
		if et != "network_connect" && et != "auth_attempt" {
			t.Fatalf("heuristic matched implausible event type %q", et)
		}
	}
	if len(probe.gotTypes) == 0 {
		t.Fatal("heuristic must restrict event types, not match everything")
	}
}

// ---------------------------------------------------------------
// "We did not look" paths — none may assert a gap.
// ---------------------------------------------------------------

func TestNonExecutedValidationIsNotApplicable(t *testing.T) {
	for _, oc := range []Outcome{OutcomeError, OutcomeSkipped} {
		probe := &fakeProbe{live: true, nearN: 0}
		c := NewDetectionCorrelator(probe)
		ev := baseEvidence()
		ev.Outcome = oc

		v := c.Evaluate(context.Background(), shared.NewID(), ev, shared.ID{})

		if v.Status != DetectionNotApplicable {
			t.Fatalf("outcome %q: status = %q, want %q", oc, v.Status, DetectionNotApplicable)
		}
		if v.Status.IsDetectionGap() {
			t.Fatalf("outcome %q: nothing executed, so a control cannot have missed it", oc)
		}
		if probe.livenessCalls != 0 {
			t.Fatalf("outcome %q: must short-circuit before touching telemetry", oc)
		}
	}
}

func TestNilProbeReportsNotEvaluated(t *testing.T) {
	c := NewDetectionCorrelator(nil)
	v := c.Evaluate(context.Background(), shared.NewID(), baseEvidence(), shared.ID{})
	if v.Status != DetectionNotEvaluated {
		t.Fatalf("status = %q, want %q", v.Status, DetectionNotEvaluated)
	}
	if v.Status.IsDetectionGap() {
		t.Fatal("an unwired correlator must never report a detection gap")
	}
}

// TestProbeErrorsNeverBecomeDetectionGaps: a DB failure must degrade to
// "we don't know", never to "your controls missed it".
func TestProbeErrorsNeverBecomeDetectionGaps(t *testing.T) {
	boom := errors.New("connection reset")
	cases := map[string]*fakeProbe{
		"liveness query failed":    {liveErr: boom},
		"correlation query failed": {corrErr: boom, live: true},
		"window query failed":      {live: true, nearErr: boom},
	}
	for name, probe := range cases {
		c := NewDetectionCorrelator(probe)
		corrID := shared.ID{}
		if name == "correlation query failed" {
			corrID = shared.NewID()
		}
		v := c.Evaluate(context.Background(), shared.NewID(), baseEvidence(), corrID)
		if v.Status != DetectionNotEvaluated {
			t.Fatalf("%s: status = %q, want %q", name, v.Status, DetectionNotEvaluated)
		}
		if v.Status.IsDetectionGap() {
			t.Fatalf("%s: a query failure must not indict a control", name)
		}
	}
}

// TestNoAssetIDCannotAssertAGap: with nothing stamped and no asset to
// scope a window to, we have not looked anywhere.
func TestNoAssetIDCannotAssertAGap(t *testing.T) {
	probe := &fakeProbe{live: true}
	c := NewDetectionCorrelator(probe)
	ev := baseEvidence()
	ev.Target.AssetID = shared.ID{}

	v := c.Evaluate(context.Background(), shared.NewID(), ev, shared.ID{})

	if v.Status != DetectionNotEvaluated {
		t.Fatalf("status = %q, want %q", v.Status, DetectionNotEvaluated)
	}
	if v.Status.IsDetectionGap() {
		t.Fatal("without a scoped window we have not looked; cannot claim a gap")
	}
}

// ---------------------------------------------------------------
// Store integration — the verdict must actually be persisted.
// ---------------------------------------------------------------

func TestEvidenceStorePersistsDetectionVerdict(t *testing.T) {
	repo := &memEvidenceRepo{}
	s := NewEvidenceStore(repo)
	s.SetDetectionCorrelator(NewDetectionCorrelator(&fakeProbe{live: false}))

	stored, err := s.Record(context.Background(), shared.NewID(), shared.NewID(), nil, baseEvidence())
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if stored.DetectionStatus != DetectionNoTelemetrySource {
		t.Fatalf("returned status = %q, want %q", stored.DetectionStatus, DetectionNoTelemetrySource)
	}
	if len(repo.rows) != 1 || repo.rows[0].DetectionStatus != DetectionNoTelemetrySource {
		t.Fatalf("persisted status = %q, want %q — the verdict must reach the repo, not just the return value",
			repo.rows[0].DetectionStatus, DetectionNoTelemetrySource)
	}
	if repo.rows[0].DetectionDetail["reason"] == nil {
		t.Fatal("persisted row must carry the reason for the verdict")
	}
}

// A store with no correlator wired must record not_evaluated — never an
// empty status (which a reader could coerce to "no detection") and
// never a gap.
func TestEvidenceStoreWithoutCorrelatorRecordsNotEvaluated(t *testing.T) {
	repo := &memEvidenceRepo{}
	s := NewEvidenceStore(repo)

	stored, err := s.Record(context.Background(), shared.NewID(), shared.NewID(), nil, baseEvidence())
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if stored.DetectionStatus != DetectionNotEvaluated {
		t.Fatalf("status = %q, want %q", stored.DetectionStatus, DetectionNotEvaluated)
	}
	if stored.DetectionStatus.IsDetectionGap() {
		t.Fatal("an unwired store must not report a detection gap")
	}
}

func TestValidDetectionStatus(t *testing.T) {
	if ValidDetectionStatus("detected") {
		t.Fatal(`"detected" is an Outcome, not a DetectionStatus — it must not validate`)
	}
	if !ValidDetectionStatus(DetectionNoTelemetrySource) {
		t.Fatal("no_telemetry_source must be a valid status")
	}
}
