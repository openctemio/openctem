package cirun

import (
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestPolicyModes(t *testing.T) {
	now := time.Now()
	sast := RunFinding{ID: shared.NewID(), Fingerprint: "s", Severity: "high", Source: "sast", RuleID: "go.sqli", Status: "new"}
	sca := RunFinding{ID: shared.NewID(), Fingerprint: "c", Severity: "critical", Source: "sca", RuleID: "CVE-1", Status: "new"}
	secret := RunFinding{ID: shared.NewID(), Fingerprint: "k", Severity: "low", Source: "secret", FindingType: "secret", Status: "new"}
	all := map[string]bool{"s": true, "c": true, "k": true}
	eval := func(m PolicyModes, fs ...RunFinding) GateVerdict {
		p := DefaultGatePolicy()
		p.Modes = m
		return Evaluate(GateInput{Policy: p, Findings: fs, NewFingerprints: all, BaselineKnown: true, Now: now})
	}

	// Comment: listed with mode comment, the gate passes.
	v := eval(PolicyModes{Capabilities: map[string]string{"sast": FindingModeComment}}, sast)
	if v.Verdict != VerdictPass || v.Summary.Blocking != 0 || len(v.Reasons) != 1 || v.Reasons[0].Mode != FindingModeComment {
		t.Fatalf("comment: %+v", v)
	}
	// Monitor: not listed, counted.
	v = eval(PolicyModes{Capabilities: map[string]string{"sca": FindingModeMonitor}}, sca)
	if v.Verdict != VerdictPass || len(v.Reasons) != 0 || v.Summary.Monitored != 1 {
		t.Fatalf("monitor: %+v", v)
	}
	// A rule's mode wins over its capability's.
	v = eval(PolicyModes{Capabilities: map[string]string{"sast": FindingModeMonitor}, Rules: map[string]string{"go.sqli": FindingModeBlock}}, sast)
	if v.Verdict != VerdictFail {
		t.Fatalf("rule block over capability monitor: %+v", v)
	}
	// A new secret blocks whatever the modes say.
	v = eval(PolicyModes{Capabilities: map[string]string{"secrets": FindingModeMonitor}}, secret)
	if v.Verdict != VerdictFail || v.Reasons[0].Code != ReasonSecret {
		t.Fatalf("secret under monitor: %+v", v)
	}
	// The policy view shows the modes.
	if v.Policy.Modes == nil || v.Policy.Modes.Capabilities["secrets"] != FindingModeMonitor {
		t.Fatalf("view: %+v", v.Policy)
	}
}

func TestPolicyModesValidateAndStrictest(t *testing.T) {
	for _, bad := range []PolicyModes{
		{Capabilities: map[string]string{"dast": "block"}},
		{Capabilities: map[string]string{"sast": "ignore"}},
		{Rules: map[string]string{"": "block"}},
		{Rules: map[string]string{"r\n": "block"}},
	} {
		if err := bad.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%+v accepted", bad)
		}
	}
	a := GatePolicy{Mode: ModeWarn, FailOnSeverity: "high", Modes: PolicyModes{Capabilities: map[string]string{"sast": FindingModeMonitor}}}
	b := GatePolicy{Mode: ModeWarn, FailOnSeverity: "high", Modes: PolicyModes{Capabilities: map[string]string{"sast": FindingModeComment, "sca": FindingModeMonitor}}}
	s := Strictest([]GatePolicy{a, b})
	// sast: the stronger of monitor and comment; sca: block where a sets nothing.
	if s.Modes.Capabilities["sast"] != FindingModeComment || s.Modes.Capabilities["sca"] != "" {
		t.Fatalf("strictest modes = %+v", s.Modes)
	}
}
