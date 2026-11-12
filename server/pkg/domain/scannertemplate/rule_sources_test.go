package scannertemplate

import "testing"

func TestParseRuleSources(t *testing.T) {
	for in, want := range map[string]RuleSources{"": "", "both": RuleSourcesBoth, " Platform ": RuleSourcesPlatform, "TENANT": RuleSourcesTenant} {
		if got, err := ParseRuleSources(in); err != nil || got != want {
			t.Errorf("ParseRuleSources(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"all", "custom", "platform,tenant"} {
		if _, err := ParseRuleSources(in); err == nil {
			t.Errorf("ParseRuleSources(%q) accepted an unknown value", in)
		}
	}
}

func TestEffectiveRuleSources(t *testing.T) {
	cases := []struct{ scan, profile, want RuleSources }{
		{"", "", RuleSourcesBoth},
		{"", RuleSourcesTenant, RuleSourcesTenant},
		{RuleSourcesPlatform, RuleSourcesTenant, RuleSourcesPlatform},
		{"bogus", "bogus", RuleSourcesBoth},
	}
	for _, c := range cases {
		if got := EffectiveRuleSources(c.scan, c.profile); got != c.want {
			t.Errorf("EffectiveRuleSources(%q, %q) = %q, want %q", c.scan, c.profile, got, c.want)
		}
	}
	if !RuleSourcesBoth.RunsTenant() || !RuleSourcesTenant.RunsTenant() || RuleSourcesPlatform.RunsTenant() {
		t.Error("RunsTenant is wrong")
	}
}
