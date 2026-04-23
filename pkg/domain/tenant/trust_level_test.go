package tenant

import (
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

func TestTrustLevel_IsValid(t *testing.T) {
	cases := []struct {
		level TrustLevel
		want  bool
	}{
		{TrustLevelPrimary, true},
		{TrustLevelHigh, true},
		{TrustLevelMedium, true},
		{TrustLevelLow, true},
		{"", false},
		{"superhigh", false},
		{"PRIMARY", false}, // case-sensitive
	}
	for _, tc := range cases {
		if got := tc.level.IsValid(); got != tc.want {
			t.Errorf("TrustLevel(%q).IsValid() = %v, want %v", tc.level, got, tc.want)
		}
	}
}

func TestTrustLevel_Outranks(t *testing.T) {
	// Ranking: Primary > High > Medium > Low > (unset/unknown).
	cases := []struct {
		a, b TrustLevel
		want bool
	}{
		{TrustLevelPrimary, TrustLevelHigh, true},
		{TrustLevelHigh, TrustLevelPrimary, false},
		{TrustLevelMedium, TrustLevelLow, true},
		{TrustLevelLow, TrustLevelMedium, false},
		{TrustLevelPrimary, TrustLevelPrimary, false}, // equal = no outrank
		{TrustLevelHigh, "", true},                    // anything beats unset
		{"", TrustLevelLow, false},                    // unset never wins
		{"bogus", TrustLevelLow, false},               // unknown never wins
	}
	for _, tc := range cases {
		if got := tc.a.Outranks(tc.b); got != tc.want {
			t.Errorf("%q.Outranks(%q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestTrustLevel_Validate(t *testing.T) {
	// Empty is valid (means "unset"); a caller that wants to forbid
	// empty levels checks that explicitly. This matches the pattern
	// used by other optional domain enums in this package.
	if err := TrustLevel("").Validate(); err != nil {
		t.Fatalf("empty TrustLevel should validate, got: %v", err)
	}

	for _, l := range AllTrustLevels() {
		if err := l.Validate(); err != nil {
			t.Errorf("%q should validate, got: %v", l, err)
		}
	}

	err := TrustLevel("custom").Validate()
	if err == nil {
		t.Fatal("unknown level should fail validation")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestDefaultTrustLevel(t *testing.T) {
	// The migration seeds every existing source at DefaultTrustLevel().
	// Changing it silently would shift precedence for every tenant on
	// upgrade — this test pins the choice.
	if DefaultTrustLevel() != TrustLevelMedium {
		t.Errorf("DefaultTrustLevel() = %v, want %v", DefaultTrustLevel(), TrustLevelMedium)
	}
}
