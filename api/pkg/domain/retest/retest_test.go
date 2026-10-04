package retest

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func TestDecide(t *testing.T) {
	reachable := CheckResult{Outcome: "detected", Summary: "target is still reachable"}
	refused := CheckResult{Outcome: "not_detected", Summary: "connection refused"}
	timedOut := CheckResult{Outcome: "inconclusive", Summary: "no response before timeout"}
	missing := CheckResult{Missing: true}

	cases := []struct {
		name         string
		check, reach CheckResult
		want         Outcome
	}{
		{"template matched → still present", CheckResult{Outcome: "detected"}, reachable, OutcomeStillPresent},
		{"template matched even if the probe failed → still present", CheckResult{Outcome: "detected"}, refused, OutcomeStillPresent},
		{"no match on a reachable target → fixed", CheckResult{Outcome: "not_detected"}, reachable, OutcomeFixed},
		// The defect this guards: nuclei prints nothing for a dead host, so the
		// sensor says not_detected. Without the probe that read as "fixed".
		{"no match, target refused → unknown, never fixed", CheckResult{Outcome: "not_detected"}, refused, OutcomeUnknown},
		{"no match, target timed out → unknown", CheckResult{Outcome: "not_detected"}, timedOut, OutcomeUnknown},
		{"no match, probe never answered → unknown", CheckResult{Outcome: "not_detected"}, missing, OutcomeUnknown},
		{"template not installed (inconclusive) → unknown", CheckResult{Outcome: "inconclusive"}, reachable, OutcomeUnknown},
		{"re-run errored → unknown", CheckResult{Outcome: "error"}, reachable, OutcomeUnknown},
		{"re-run never answered → unknown", missing, reachable, OutcomeUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reason := Decide(c.check, c.reach)
			if got != c.want {
				t.Fatalf("Decide = %s (%s), want %s", got, reason, c.want)
			}
			if reason == "" {
				t.Errorf("no reason given")
			}
		})
	}

	if _, reason := Decide(CheckResult{Outcome: "not_detected"}, refused); reason != "target unreachable: connection refused" {
		t.Errorf("unreachable reason = %q", reason)
	}
}

func TestNextStatus(t *testing.T) {
	type want struct {
		next   vulnerability.FindingStatus
		change bool
	}
	S := func(s string) vulnerability.FindingStatus { return vulnerability.FindingStatus(s) }
	cases := []struct {
		prior   string
		outcome Outcome
		want    want
	}{
		{"new", OutcomeFixed, want{"resolved", true}},
		{"confirmed", OutcomeFixed, want{"resolved", true}},
		{"in_progress", OutcomeFixed, want{"resolved", true}},
		{"fix_applied", OutcomeFixed, want{"resolved", true}},
		{"validated_fixed", OutcomeFixed, want{"resolved", true}},
		{"resolved", OutcomeFixed, want{"resolved", false}},

		{"resolved", OutcomeStillPresent, want{"confirmed", true}}, // regression reopen
		{"fix_applied", OutcomeStillPresent, want{"in_progress", true}},
		{"validated_fixed", OutcomeStillPresent, want{"confirmed", true}},
		{"confirmed", OutcomeStillPresent, want{"confirmed", false}},
		{"in_progress", OutcomeStillPresent, want{"in_progress", false}},

		{"confirmed", OutcomeUnknown, want{"confirmed", false}},
		{"resolved", OutcomeUnknown, want{"resolved", false}},

		// Deliberate dispositions and pentest states are never moved.
		{"false_positive", OutcomeStillPresent, want{"false_positive", false}},
		{"accepted", OutcomeStillPresent, want{"accepted", false}},
		{"duplicate", OutcomeFixed, want{"duplicate", false}},
		{"verified", OutcomeStillPresent, want{"verified", false}},
	}
	for _, c := range cases {
		next, change := NextStatus(S(c.prior), c.outcome)
		if next != c.want.next || change != c.want.change {
			t.Errorf("NextStatus(%s, %s) = (%s, %v), want (%s, %v)", c.prior, c.outcome, next, change, c.want.next, c.want.change)
		}
	}
}

func TestIsRegression(t *testing.T) {
	if !IsRegression(vulnerability.FindingStatusResolved, vulnerability.FindingStatusConfirmed) {
		t.Error("resolved → confirmed is a regression")
	}
	if IsRegression(vulnerability.FindingStatusValidatedFixed, vulnerability.FindingStatusConfirmed) {
		t.Error("validated_fixed → confirmed refutes a downgrade; it is not a regression of a fix")
	}
}

func TestEligibleStatusesMatchesEligibleStatus(t *testing.T) {
	for _, s := range EligibleStatuses() {
		if !EligibleStatus(vulnerability.FindingStatus(s)) {
			t.Errorf("%s listed but not eligible", s)
		}
	}
	if len(EligibleStatuses()) != len(eligibleStatuses) {
		t.Errorf("EligibleStatuses has %d entries, the rule table %d", len(EligibleStatuses()), len(eligibleStatuses))
	}
}
