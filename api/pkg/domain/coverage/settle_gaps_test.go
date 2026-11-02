package coverage

import (
	"encoding/json"
	"testing"
)

func gapTask(targets []string, result string) []TaskResult {
	return []TaskResult{{Status: "completed", Targets: targets, Result: json.RawMessage(result)}}
}

// An older sensor sends no per-target outcomes, only coverage gaps: a host
// an edge protection blocked is never covered, and the outcome and vendor
// are mapped like the sensor's own per-target outcomes.
func TestVerdicts_OlderSensorGaps(t *testing.T) {
	gaps := `{"metadata": {"coverage_gaps_total": 5, "coverage_gaps": [
		{"host": "blocked.example.test", "reason": "blocked", "edge": "blocked", "vendor": "DataDome"},
		{"host": "chall.example.test", "reason": "blocked", "edge": "challenged", "vendor": "cloudflare"},
		{"host": "slow.example.test", "reason": "rate_floor"},
		{"host": "dead.example.test", "reason": "breaker_open"},
		{"host": "proxy.example.test", "reason": "proxy_unavailable"}]}}`
	v := Verdicts(gapTask([]string{"blocked.example.test", "chall.example.test", "slow.example.test",
		"dead.example.test", "proxy.example.test", "fine.example.test", "https://Blocked.example.test:8443/x"}, gaps), nil)
	want := map[string][2]string{
		"blocked.example.test":                {"edge_blocked", "datadome"},
		"chall.example.test":                  {"edge_challenged", "cloudflare"},
		"slow.example.test":                   {"rate_limited", ""},
		"dead.example.test":                   {"unreachable", ""},
		"proxy.example.test":                  {"sensor_network_fault", ""},
		"https://blocked.example.test:8443/x": {"edge_blocked", "datadome"},
	}
	for target, w := range want {
		got := v[target]
		if got.Kind != VerdictFailed || got.Outcome != w[0] || got.Vendor != w[1] {
			t.Errorf("%s = %+v, want failed %s vendor %q", target, got, w[0], w[1])
		}
	}
	if v["dead.example.test"].Error != "stopped answering" {
		t.Errorf("breaker error = %q", v["dead.example.test"].Error)
	}
	if !IsPlatformSide(v["proxy.example.test"].Outcome) {
		t.Error("a proxy failure must be platform side")
	}
	for _, o := range []string{"edge_blocked", "edge_challenged", "rate_limited"} {
		if IsPlatformSide(o) {
			t.Errorf("%s must count against the target", o)
		}
	}
	// five gaps listed, five counted: the clean host is covered.
	if v["fine.example.test"].Kind != VerdictCovered {
		t.Errorf("fine = %+v, want covered", v["fine.example.test"])
	}
}

// A done outcome for a host the result also lists as a gap does not cover it.
func TestVerdicts_GapBeatsDoneOutcome(t *testing.T) {
	v := Verdicts(gapTask([]string{"a.example.test", "b.example.test"}, `{
		"target_outcomes": [{"target": "a.example.test", "state": "done"}, {"target": "b.example.test", "state": "done"}],
		"metadata": {"coverage_gaps_total": 1, "coverage_gaps": [{"host": "a.example.test", "reason": "blocked", "vendor": "akamai"}]}}`), nil)
	if a := v["a.example.test"]; a.Kind != VerdictFailed || a.Outcome != "edge_blocked" || a.Vendor != "akamai" {
		t.Errorf("a = %+v", a)
	}
	if v["b.example.test"].Kind != VerdictCovered {
		t.Errorf("b = %+v", v["b.example.test"])
	}
}

// A list shorter than its count leaves unknown hosts: nothing of an
// older sensor's task is covered.
func TestVerdicts_ShortGapListCoversNothing(t *testing.T) {
	v := Verdicts(gapTask([]string{"a.example.test", "b.example.test"}, `{
		"metadata": {"coverage_gaps_total": 3, "coverage_gaps": [{"host": "a.example.test", "reason": "rate_floor"}]}}`), nil)
	if a := v["a.example.test"]; a.Outcome != "rate_limited" {
		t.Errorf("a = %+v", a)
	}
	if b := v["b.example.test"]; b.Kind != VerdictFailed || b.Outcome != OutcomeUnfinished || b.Error == "" {
		t.Errorf("b = %+v, want unfinished with an explanation", b)
	}
	// An entry without a host is as unknown as a missing one.
	v = Verdicts(gapTask([]string{"c.example.test"}, `{"metadata": {"coverage_gaps_total": 1, "coverage_gaps": [{"reason": "blocked"}]}}`), nil)
	if c := v["c.example.test"]; c.Kind == VerdictCovered {
		t.Errorf("c = %+v, want not covered", c)
	}
}

// An unknown gap reason never covers the host.
func TestVerdicts_UnknownGapReasonIsNotCovered(t *testing.T) {
	v := Verdicts(gapTask([]string{"a.example.test"}, `{"metadata": {"coverage_gaps_total": 1,
		"coverage_gaps": [{"host": "a.example.test", "reason": "mystery"}]}}`), nil)
	if a := v["a.example.test"]; a.Kind != VerdictFailed || a.Outcome != OutcomeUnfinished {
		t.Errorf("a = %+v", a)
	}
}

// The vendor of an edge outcome is carried, as a token only.
func TestVerdicts_VendorFromOutcomes(t *testing.T) {
	v := Verdicts(gapTask([]string{"a.example.test", "b.example.test", "c.example.test"}, `{"target_outcomes": [
		{"target": "a.example.test", "state": "failed", "class": "edge_blocked", "vendor": "datadome"},
		{"target": "b.example.test", "state": "skipped", "class": "edge_challenged", "vendor": "cloudflare"},
		{"target": "c.example.test", "state": "failed", "class": "rate_limited"}]}`), nil)
	if a := v["a.example.test"]; a.Kind != VerdictFailed || a.Outcome != "edge_blocked" || a.Vendor != "datadome" {
		t.Errorf("a = %+v", a)
	}
	if b := v["b.example.test"]; b.Kind != VerdictFailed || b.Outcome != "edge_challenged" || b.Vendor != "cloudflare" {
		t.Errorf("b = %+v", b)
	}
	if c := v["c.example.test"]; c.Outcome != "rate_limited" || c.Vendor != "" {
		t.Errorf("c = %+v", c)
	}
}
