package retest

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/evidence"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

const matchedAt = "https://shop.example.com/wp-admin/js/theme.js"

// attempt is one HTTP exchange a re-run reported.
func attempt(url string, status int) []evidence.Item {
	it := evidence.Item{Kind: evidence.KindHTTPExchange, HTTP: &evidence.HTTP{
		Request: &evidence.HTTPRequest{Method: "GET", URL: url},
	}}
	if status > 0 {
		it.HTTP.Response = &evidence.HTTPResponse{Status: status}
	}
	return []evidence.Item{it}
}

func TestDecide(t *testing.T) {
	reachable := CheckResult{Outcome: "detected", Summary: "target is still reachable"}
	refused := CheckResult{Outcome: "not_detected", Summary: "connection refused"}
	missing := CheckResult{Missing: true}
	noMatch := func(items []evidence.Item) CheckResult { return CheckResult{Outcome: "not_detected", Evidence: items} }

	cases := []struct {
		name         string
		check, reach CheckResult
		want         Outcome
		code         ReasonCode
	}{
		{"matched → still vulnerable", CheckResult{Outcome: "detected"}, refused, OutcomeStillVulnerable, ReasonMatched},
		{"no match, endpoint answered 200 → confirmed fixed", noMatch(attempt(matchedAt, 200)), reachable, OutcomeConfirmedFixed, ReasonNotMatched},
		{"no match, endpoint answered 404 → confirmed fixed", noMatch(attempt(matchedAt, 404)), missing, OutcomeConfirmedFixed, ReasonNotMatched},
		// The owner's case (2026-10-07): the re-run requested the path twice.
		{"no match at another path → endpoint mismatch", noMatch(attempt(matchedAt+"/wp-admin/js/theme.js", 404)), reachable, OutcomeInconclusive, ReasonEndpointMismatch},
		{"no match, 403 → blocked", noMatch(attempt(matchedAt, 403)), reachable, OutcomeInconclusive, ReasonBlocked},
		{"no match, 429 → blocked", noMatch(attempt(matchedAt, 429)), reachable, OutcomeInconclusive, ReasonBlocked},
		{"no match, 401 → auth changed", noMatch(attempt(matchedAt, 401)), reachable, OutcomeInconclusive, ReasonAuthChanged},
		{"no match, 503 → server error", noMatch(attempt(matchedAt, 503)), reachable, OutcomeInconclusive, ReasonServerError},
		{"no match, no response → unreachable", noMatch(attempt(matchedAt, 0)), reachable, OutcomeInconclusive, ReasonUnreachable},
		// A bare "not detected" on a host that answers a TCP probe proves nothing.
		{"no match, no evidence, host reachable → not reproduced", noMatch(nil), reachable, OutcomeNotReproduced, ReasonNoEndpointProof},
		{"no match, no evidence, host refused → unreachable", noMatch(nil), refused, OutcomeInconclusive, ReasonUnreachable},
		{"no match, no evidence, probe missing → unreachable", noMatch(nil), missing, OutcomeInconclusive, ReasonUnreachable},
		{"template not installed → inconclusive", CheckResult{Outcome: "inconclusive"}, reachable, OutcomeInconclusive, ReasonError},
		{"re-run never answered → no result", missing, reachable, OutcomeInconclusive, ReasonNoResult},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := Decide(c.check, c.reach, matchedAt)
			if v.Outcome != c.want || v.Code != c.code {
				t.Fatalf("Decide = %s/%s (%s), want %s/%s", v.Outcome, v.Code, v.Reason, c.want, c.code)
			}
			if v.Reason == "" {
				t.Errorf("no reason given")
			}
		})
	}
}

func TestDecideEndpointIgnoresQueryValuesAndDefaultPorts(t *testing.T) {
	at := "https://shop.example.com/api?token=[REDACTED]&id=7" // as the sensor stores it
	v := Decide(CheckResult{Outcome: "not_detected", Evidence: attempt("https://SHOP.example.com:443/api?id=8&token=other", 200)},
		CheckResult{Outcome: "detected"}, at)
	if v.Outcome != OutcomeConfirmedFixed {
		t.Fatalf("got %s (%s)", v.Outcome, v.Reason)
	}
	// Another parameter set is another endpoint.
	v = Decide(CheckResult{Outcome: "not_detected", Evidence: attempt("https://shop.example.com/api?id=8", 200)},
		CheckResult{Outcome: "detected"}, at)
	if v.Code != ReasonEndpointMismatch {
		t.Fatalf("got %s", v.Code)
	}
}

func TestDecideReasonsCarryNoSecrets(t *testing.T) {
	v := Decide(CheckResult{Outcome: "detected", Summary: "matched at https://h/x?access_token=supersecret123"},
		CheckResult{}, "https://h/x")
	if strings.Contains(v.Reason, "supersecret123") {
		t.Fatalf("reason leaks the token: %q", v.Reason)
	}
	v = Decide(CheckResult{Outcome: "not_detected", Evidence: attempt("https://h/x?access_token=supersecret123", 200)},
		CheckResult{Outcome: "detected"}, "https://h/x?access_token=other")
	if strings.Contains(v.Reason, "supersecret123") || !strings.Contains(v.Reason, "access_token=…") {
		t.Fatalf("reason = %q", v.Reason)
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
		auto    bool
		want    want
	}{
		// A confirmed fix awaits a person, unless the tenant auto-resolves.
		{"new", OutcomeConfirmedFixed, false, want{"validated_fixed", true}},
		{"confirmed", OutcomeConfirmedFixed, false, want{"validated_fixed", true}},
		{"fix_applied", OutcomeConfirmedFixed, false, want{"validated_fixed", true}},
		{"not_observed", OutcomeConfirmedFixed, false, want{"validated_fixed", true}},
		{"validated_fixed", OutcomeConfirmedFixed, false, want{"validated_fixed", false}},
		{"resolved", OutcomeConfirmedFixed, false, want{"resolved", false}},
		{"confirmed", OutcomeConfirmedFixed, true, want{"resolved", true}},
		{"validated_fixed", OutcomeConfirmedFixed, true, want{"resolved", true}},
		{"resolved", OutcomeConfirmedFixed, true, want{"resolved", false}},

		{"resolved", OutcomeStillVulnerable, false, want{"confirmed", true}}, // regression reopen
		{"fix_applied", OutcomeStillVulnerable, false, want{"in_progress", true}},
		{"validated_fixed", OutcomeStillVulnerable, false, want{"confirmed", true}},
		{"confirmed", OutcomeStillVulnerable, false, want{"confirmed", false}},

		// Nothing else moves a finding, auto-resolve or not.
		{"confirmed", OutcomeNotReproduced, true, want{"confirmed", false}},
		{"fix_applied", OutcomeNotReproduced, true, want{"fix_applied", false}},
		{"confirmed", OutcomeInconclusive, true, want{"confirmed", false}},
		{"resolved", OutcomeInconclusive, true, want{"resolved", false}},

		// Deliberate dispositions and pentest states are never moved.
		{"false_positive", OutcomeStillVulnerable, false, want{"false_positive", false}},
		{"accepted", OutcomeStillVulnerable, false, want{"accepted", false}},
		{"duplicate", OutcomeConfirmedFixed, true, want{"duplicate", false}},
		{"verified", OutcomeStillVulnerable, false, want{"verified", false}},
	}
	for _, c := range cases {
		next, change := NextStatus(S(c.prior), c.outcome, c.auto)
		if next != c.want.next || change != c.want.change {
			t.Errorf("NextStatus(%s, %s, auto=%v) = (%s, %v), want (%s, %v)", c.prior, c.outcome, c.auto, next, change, c.want.next, c.want.change)
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
