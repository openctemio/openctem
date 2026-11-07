package tenant

import "testing"

// The widest range one scan target may name (RFC-151): a /16 by default for
// every organization (an unset value included), a /8 only when the
// organization opts in, never wider than a /8.
func TestScopeSettingsRangePrefix(t *testing.T) {
	if got := (ScopeSettings{}).RangePrefix(); got != 16 {
		t.Fatalf("default = /%d, want /16", got)
	}
	if got := (ScopeSettings{}).RangeHostBits(); got != 16 {
		t.Fatalf("default host bits = %d, want 16", got)
	}
	if got := (ScopeSettings{MaxRangePrefix: 8}).RangeHostBits(); got != 24 {
		t.Fatalf("/8 = %d host bits", got)
	}
	for _, p := range []int{8, 12, 16, 24} {
		if err := (ScopeSettings{MaxRangePrefix: p}).Validate(); err != nil {
			t.Fatalf("/%d refused: %v", p, err)
		}
	}
	for _, p := range []int{-1, 7, 25, 32} {
		if err := (ScopeSettings{MaxRangePrefix: p}).Validate(); err == nil {
			t.Fatalf("/%d accepted", p)
		}
	}
}

// Raising the widest range (a lower prefix) is a widening; lowering is not,
// and an unset value counts as the /16 default.
func TestRangeWidened(t *testing.T) {
	cases := []struct {
		before, after int
		want          bool
	}{
		{0, 8, true}, {16, 12, true}, {0, 16, false}, {8, 16, false}, {8, 0, false}, {16, 24, false},
	}
	for _, c := range cases {
		if got := RangeWidened(ScopeSettings{MaxRangePrefix: c.before}, ScopeSettings{MaxRangePrefix: c.after}); got != c.want {
			t.Errorf("/%d -> /%d: widened = %v, want %v", c.before, c.after, got, c.want)
		}
	}
}
