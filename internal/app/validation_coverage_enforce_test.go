package app

import (
	"errors"
	"testing"
)

// Enforce-level tests — the cycle-close wiring calls Enforce with the
// default thresholds; these tests lock the behaviour so a regression
// in DefaultThresholds or Enforce doesn't silently let a cycle close
// with uncovered P0/P1 findings.

func TestEnforce_DefaultThresholds_AllMet_NoError(t *testing.T) {
	c := ValidationCoverage{
		P0Total: 5, P0WithEvidence: 5,
		P1Total: 4, P1WithEvidence: 4,
		P2Total: 10, P2WithEvidence: 10,
	}
	if err := Enforce(c, DefaultThresholds); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestEnforce_DefaultThresholds_P0Missing_ErrorsSLO(t *testing.T) {
	c := ValidationCoverage{
		P0Total: 10, P0WithEvidence: 9, // 90% < 100%
	}
	err := Enforce(c, DefaultThresholds)
	if err == nil {
		t.Fatal("expected SLO breach error")
	}
	if !errors.Is(err, ErrCoverageBelowSLO) {
		t.Fatalf("want ErrCoverageBelowSLO, got %v", err)
	}
}

func TestEnforce_DefaultThresholds_P2At80_NoError(t *testing.T) {
	// P2 threshold is 80%; exactly at target should pass.
	c := ValidationCoverage{P2Total: 10, P2WithEvidence: 8}
	if err := Enforce(c, DefaultThresholds); err != nil {
		t.Fatalf("expected 80%% to pass P2 threshold, got %v", err)
	}
}

func TestEnforce_DefaultThresholds_P3AlwaysPasses(t *testing.T) {
	// P3 threshold is 0 — class not enforced.
	c := ValidationCoverage{P3Total: 100, P3WithEvidence: 0}
	if err := Enforce(c, DefaultThresholds); err != nil {
		t.Fatalf("P3 should be unenforced, got %v", err)
	}
}

func TestEnforce_EmptyCycle_TriviallyMet(t *testing.T) {
	// Zero total per class → Pct returns 100 → all thresholds met.
	c := ValidationCoverage{}
	if err := Enforce(c, DefaultThresholds); err != nil {
		t.Fatalf("empty cycle should pass, got %v", err)
	}
}

func TestEnforce_MessageListsAllBreaches(t *testing.T) {
	// Both P0 and P1 below threshold — error should mention both.
	c := ValidationCoverage{
		P0Total: 10, P0WithEvidence: 7, // 70% < 100%
		P1Total: 10, P1WithEvidence: 5, // 50% < 100%
	}
	err := Enforce(c, DefaultThresholds)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	// Human-readable message must name both classes so the operator
	// can fix them before retrying close.
	for _, class := range []string{"P0", "P1"} {
		if !contains(msg, class) {
			t.Errorf("expected message to mention %s, got %q", class, msg)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
