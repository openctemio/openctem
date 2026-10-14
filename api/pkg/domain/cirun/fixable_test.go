package cirun

import (
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// With FixableOnly, a dependency vulnerability that has no fixed version is
// listed but does not block on severity; one with a fix blocks; KEV blocks
// either way; code findings are not affected.
func TestFixableOnly(t *testing.T) {
	finding := func(source string, fix, kev bool) RunFinding {
		return RunFinding{ID: shared.NewID(), Fingerprint: shared.NewID().String(), Title: "x", Severity: "high",
			Status: "open", Source: source, FindingType: "vulnerability", FixAvailable: fix, IsInKEV: kev}
	}
	policy := DefaultGatePolicy()
	policy.NewFindingsOnly = false
	policy.FixableOnly = true
	judge := func(p GatePolicy, f RunFinding) GateVerdict {
		return Evaluate(GateInput{Policy: p, Findings: []RunFinding{f}, BaselineKnown: true, Now: time.Now()})
	}

	v := judge(policy, finding("sca", false, false))
	if v.Verdict != VerdictPass || len(v.Reasons) != 1 || v.Reasons[0].Mode != FindingModeComment ||
		!strings.Contains(v.Reasons[0].Message, "no fixed version") {
		t.Fatalf("unfixable: %+v", v)
	}
	if v := judge(policy, finding("sca", true, false)); v.Verdict != VerdictFail {
		t.Fatalf("fixable: %s", v.Verdict)
	}
	if v := judge(policy, finding("container", false, true)); v.Verdict != VerdictFail || v.Reasons[0].Code != ReasonKEV {
		t.Fatalf("unfixable but KEV: %+v", v)
	}
	sast := finding("sast", false, false)
	sast.FindingType = "sast"
	if v := judge(policy, sast); v.Verdict != VerdictFail {
		t.Fatalf("code finding: %s", v.Verdict)
	}
	// Off (the default): an unfixable vulnerability blocks as before.
	policy.FixableOnly = false
	if v := judge(policy, finding("sca", false, false)); v.Verdict != VerdictFail {
		t.Fatalf("default: %s", v.Verdict)
	}
	// Strictest of two policies: one that blocks unfixable ones wins.
	a, b := DefaultGatePolicy(), DefaultGatePolicy()
	a.FixableOnly = true
	if Strictest([]GatePolicy{a, b}).FixableOnly {
		t.Fatal("strictest kept fixable only")
	}
}
