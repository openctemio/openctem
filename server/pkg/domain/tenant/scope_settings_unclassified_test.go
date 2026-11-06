package tenant

import "testing"

func TestScopeSettingsUnclassified(t *testing.T) {
	if got := (ScopeSettings{}).Unclassified(); got != UnclassifiedLowImpact {
		t.Fatalf("default = %s", got)
	}
	for _, v := range []string{"", UnclassifiedOff, UnclassifiedLowImpact, UnclassifiedFull} {
		if err := (ScopeSettings{UnclassifiedScans: v}).Validate(); err != nil {
			t.Fatalf("%q: %v", v, err)
		}
	}
	if err := (ScopeSettings{UnclassifiedScans: "everything"}).Validate(); err == nil {
		t.Fatal("an unknown mode must be refused")
	}
}
