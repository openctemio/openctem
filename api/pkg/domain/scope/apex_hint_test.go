package scope

import "testing"

func TestCoversOnlySubdomainsOf(t *testing.T) {
	cases := []struct {
		tt      TargetType
		pattern string
		value   string
		want    bool
	}{
		{TargetTypeDomain, "*.x.com", "x.com", true},
		{TargetTypeDomain, "**.X.com.", "x.com", true},
		{TargetTypeDomain, "*.x.com", "a.x.com", false},
		{TargetTypeDomain, "*.x.com", "y.com", false},
		{TargetTypeDomain, "x.com", "x.com", false},
		{TargetTypeIPAddress, "*.x.com", "x.com", false},
		{TargetTypeDomain, "*.x.com", "*.x.com", false},
	}
	for _, c := range cases {
		if got := CoversOnlySubdomainsOf(c.tt, c.pattern, c.value); got != c.want {
			t.Errorf("%s %q vs %q = %v, want %v", c.tt, c.pattern, c.value, got, c.want)
		}
	}
	// The matching rule itself is unchanged: the wildcard never matches the apex.
	if MatchesPattern(TargetTypeDomain, "*.x.com", "x.com") {
		t.Fatal("wildcard must not match the apex")
	}
}
