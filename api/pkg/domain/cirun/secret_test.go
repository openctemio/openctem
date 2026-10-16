package cirun

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestSecretPages(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name string
		f    RunFinding
		want bool
	}{
		{"provider key, validity unknown", RunFinding{FindingType: "secret", RuleID: "aws-access-token"}, true},
		{"provider key, validated true", RunFinding{FindingType: "secret", RuleID: "github-pat", SecretValid: &yes}, true},
		{"validated false", RunFinding{FindingType: "secret", RuleID: "aws-access-token", SecretValid: &no}, false},
		{"hard-coded password literal", RunFinding{FindingType: "secret", RuleID: "hardcoded-password"}, false},
		{"generic api key", RunFinding{FindingType: "secret", RuleID: "generic-api-key"}, false},
		{"generic but validated true still follows the rule", RunFinding{FindingType: "secret", RuleID: "generic-api-key", SecretValid: &yes}, false},
		{"not a secret", RunFinding{FindingType: "vulnerability", RuleID: "aws-access-token"}, false},
	}
	for _, c := range cases {
		if got := c.f.SecretPages(); got != c.want {
			t.Errorf("%s: SecretPages = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSecretIdentityPrefersTheKeyedFingerprint(t *testing.T) {
	if got := (RunFinding{Fingerprint: "f", SecretFingerprint: "s"}).SecretIdentity(); got != "s" {
		t.Fatalf("identity = %q", got)
	}
	if got := (RunFinding{Fingerprint: "f"}).SecretIdentity(); got != "f" {
		t.Fatalf("identity = %q", got)
	}
}

// A dead or heuristic secret follows the severity policy instead of always
// blocking; a provider key still blocks whatever its severity.
func TestEvaluate_SecretClassification(t *testing.T) {
	no := false
	now := time.Now()
	mk := func(rule string, valid *bool, sev string) RunFinding {
		return RunFinding{ID: shared.NewID(), Fingerprint: rule, Severity: sev, FindingType: "secret", Status: "new", RuleID: rule, SecretValid: valid}
	}
	eval := func(fs ...RunFinding) GateVerdict {
		fp := map[string]bool{}
		for _, f := range fs {
			fp[f.Fingerprint] = true
		}
		return Evaluate(GateInput{Policy: DefaultGatePolicy(), PolicySource: ScopeDefault, Findings: fs, NewFingerprints: fp,
			BaselineKnown: true, BaselineBranch: "main", Now: now})
	}
	if v := eval(mk("aws-access-token", nil, "low")); v.Verdict != VerdictFail || v.Reasons[0].Code != ReasonSecret {
		t.Fatalf("provider key must block: %+v", v)
	}
	if v := eval(mk("aws-access-token", &no, "low")); v.Verdict != VerdictPass {
		t.Fatalf("a dead secret must follow the severity policy (low passes): %+v", v)
	}
	if v := eval(mk("hardcoded-password", nil, "low")); v.Verdict != VerdictPass {
		t.Fatalf("a hard-coded password literal must not block at low severity: %+v", v)
	}
	// ...and a heuristic hit at high severity is judged by the severity rule, not the secret rule.
	if v := eval(mk("hardcoded-password", nil, "high")); v.Verdict != VerdictFail || v.Reasons[0].Code != ReasonSeverity {
		t.Fatalf("a heuristic hit at high severity follows severity: %+v", v)
	}
}
