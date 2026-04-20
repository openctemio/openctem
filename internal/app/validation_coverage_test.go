package app

import (
	"errors"
	"testing"
)

// SLO-enforcement tests.

func TestCoverage_Pct(t *testing.T) {
	c := ValidationCoverage{
		P0Total: 10, P0WithEvidence: 10,
		P1Total: 20, P1WithEvidence: 19,
		P2Total: 0, P2WithEvidence: 0,
	}
	if got := c.Pct("P0"); got != 100 {
		t.Errorf("P0 = %v, want 100", got)
	}
	if got := c.Pct("P1"); got != 95 {
		t.Errorf("P1 = %v, want 95", got)
	}
	// Zero-total class returns 100 (trivially met).
	if got := c.Pct("P2"); got != 100 {
		t.Errorf("P2 = %v, want 100 when total=0", got)
	}
	if got := c.Pct("unknown"); got != 0 {
		t.Errorf("unknown class should return 0, got %v", got)
	}
}

func TestEnforce_AllMet(t *testing.T) {
	c := ValidationCoverage{
		P0Total: 5, P0WithEvidence: 5,
		P1Total: 5, P1WithEvidence: 5,
		P2Total: 10, P2WithEvidence: 9, // 90% > 80%
	}
	if err := Enforce(c, DefaultThresholds); err != nil {
		t.Fatalf("want nil, got %v", err)
	}
}

func TestEnforce_P0Breached(t *testing.T) {
	c := ValidationCoverage{
		P0Total: 10, P0WithEvidence: 9, // 90% < 100%
		P1Total: 0,
	}
	err := Enforce(c, DefaultThresholds)
	if !errors.Is(err, ErrCoverageBelowSLO) {
		t.Fatalf("want ErrCoverageBelowSLO, got %v", err)
	}
}

func TestEnforce_P2BreachedButP0P1Met(t *testing.T) {
	c := ValidationCoverage{
		P0Total: 2, P0WithEvidence: 2,
		P1Total: 2, P1WithEvidence: 2,
		P2Total: 10, P2WithEvidence: 5, // 50% < 80%
	}
	err := Enforce(c, DefaultThresholds)
	if !errors.Is(err, ErrCoverageBelowSLO) {
		t.Fatalf("want ErrCoverageBelowSLO, got %v", err)
	}
}

func TestEnforce_P3IgnoredByDefault(t *testing.T) {
	// Default thresholds have P3 at 0% → not enforced.
	c := ValidationCoverage{
		P0Total: 0, P1Total: 0, P2Total: 0,
		P3Total: 100, P3WithEvidence: 0,
	}
	if err := Enforce(c, DefaultThresholds); err != nil {
		t.Fatalf("P3 should not be enforced: %v", err)
	}
}

func TestEnforce_CustomThresholds(t *testing.T) {
	c := ValidationCoverage{
		P0Total: 10, P0WithEvidence: 8,
	}
	// Lower threshold → passes.
	err := Enforce(c, CoverageThresholds{P0: 50})
	if err != nil {
		t.Fatalf("custom low threshold should pass: %v", err)
	}
	// Higher threshold → fails.
	err = Enforce(c, CoverageThresholds{P0: 90})
	if !errors.Is(err, ErrCoverageBelowSLO) {
		t.Fatalf("custom high threshold should fail: %v", err)
	}
}

func TestEnforce_ZeroTotalIsTriviallyMet(t *testing.T) {
	// Empty tenant / fresh cycle: no findings at all must pass.
	c := ValidationCoverage{}
	if err := Enforce(c, DefaultThresholds); err != nil {
		t.Fatalf("empty cycle must pass: %v", err)
	}
}
