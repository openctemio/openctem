package tenant

import "testing"

// The widest range one scan target may name (RFC-151): a /8 by default,
// lowered by the organization, never wider than a /8.
func TestScopeSettingsRangePrefix(t *testing.T) {
	if got := (ScopeSettings{}).RangePrefix(); got != 8 {
		t.Fatalf("default = /%d, want /8", got)
	}
	if got := (ScopeSettings{}).RangeHostBits(); got != 24 {
		t.Fatalf("default host bits = %d, want 24", got)
	}
	if got := (ScopeSettings{MaxRangePrefix: 16}).RangeHostBits(); got != 16 {
		t.Fatalf("/16 = %d host bits", got)
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
