package sensor

import (
	"encoding/json"
	"testing"
)

func boolPtr(b bool) *bool { return &b }

// A sensor that reports allow_private false, with or without a policy
// file, gets no job naming a private address (research 466 D8); one that
// does not report it is left to the sensor.
func TestAccepts_TopLevelAllowPrivate(t *testing.T) {
	private := Job{Type: "scan", Tool: "nuclei", NetworkTarget: true, Private: true, PrivateAddress: true}
	public := Job{Type: "scan", Tool: "nuclei", NetworkTarget: true}
	off := &LocalPolicyReport{State: LocalPolicyAbsent, AllowPrivate: boolPtr(false)}
	on := &LocalPolicyReport{State: LocalPolicyAbsent, AllowPrivate: boolPtr(true)}
	old := &LocalPolicyReport{State: LocalPolicyAbsent}
	if r := Accepts(off, private, DispatchOptions{}); r == nil || r.Rule != RuleTargetsAllowPrivate || r.Layer != RefusalLayerLocal {
		t.Fatalf("absent policy with the switch off: %+v", r)
	}
	if r := Accepts(off, public, DispatchOptions{}); r != nil {
		t.Fatalf("a public job refused: %+v", r)
	}
	for name, rep := range map[string]*LocalPolicyReport{"on": on, "unreported": old, "no report": nil} {
		if r := Accepts(rep, private, DispatchOptions{}); r != nil {
			t.Errorf("%s: refused %+v", name, r)
		}
	}
	// An enforced policy whose summary allows private ranges, on a host
	// whose switch is off, is refused by the top-level field.
	enforced := &LocalPolicyReport{State: LocalPolicyEnforced, AllowPrivate: boolPtr(false),
		Summary: &LocalPolicySummary{TargetsAllow: -1, AllowPrivate: true}}
	if r := Accepts(enforced, private, DispatchOptions{}); r == nil || r.Rule != RuleTargetsAllowPrivate {
		t.Fatalf("enforced, switch off: %+v", r)
	}
}

func TestLocalPolicyReport_AllowPrivateSanitizeAndMerge(t *testing.T) {
	var in LocalPolicyReport
	if err := json.Unmarshal([]byte(`{"state":"absent","allow_private":false}`), &in); err != nil {
		t.Fatal(err)
	}
	out := SanitizeLocalPolicyReport(&in)
	if out.AllowPrivate == nil || *out.AllowPrivate || !out.RefusesPrivate() {
		t.Fatalf("sanitized %+v", out)
	}
	*in.AllowPrivate = true
	if *out.AllowPrivate {
		t.Fatal("the sanitized report shares the input's pointer")
	}
	if got := SanitizeLocalPolicyReport(&LocalPolicyReport{State: LocalPolicyAbsent}); got.AllowPrivate != nil || got.RefusesPrivate() {
		t.Fatalf("unreported %+v", got)
	}
	// A report without the field (an older SDK) keeps what the same policy
	// reported before.
	stored := &LocalPolicyReport{State: LocalPolicyAbsent, AllowPrivate: boolPtr(true)}
	if m := MergeLocalPolicyReport(stored, &LocalPolicyReport{State: LocalPolicyAbsent}); m.AllowPrivate == nil || !*m.AllowPrivate {
		t.Fatalf("merged %+v", m)
	}
	if m := MergeLocalPolicyReport(stored, &LocalPolicyReport{State: LocalPolicyAbsent, AllowPrivate: boolPtr(false)}); !m.RefusesPrivate() {
		t.Fatalf("a new false lost: %+v", m)
	}
	var nilReport *LocalPolicyReport
	if nilReport.RefusesPrivate() {
		t.Fatal("no report refuses private")
	}
}
