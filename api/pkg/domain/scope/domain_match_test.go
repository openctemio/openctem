package scope

import "testing"

// "*.example.com" names example.com and every name below it (RFC-054 §4.1,
// owner decision S1), the meaning seeds, verified domains and the active-scan
// gate already had. A scope target and an exclusion use the same matcher, so
// the subdomains without the apex are "*.example.com" plus an exclusion of
// exactly "example.com".
func TestMatchDomain_Semantics(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		value   string
		want    bool
	}{
		// Exact names.
		{"exact", "example.com", "example.com", true},
		{"exact does not cover subdomain", "example.com", "www.example.com", false},
		{"exact other name", "example.com", "example.org", false},

		// Wildcard: the apex and every subdomain.
		{"wildcard subdomain", "*.example.com", "www.example.com", true},
		{"wildcard deep subdomain", "*.example.com", "a.b.c.example.com", true},
		{"wildcard matches apex", "*.example.com", "example.com", true},
		{"wildcard lookalike suffix", "*.example.com", "evilexample.com", false},
		{"wildcard lookalike label", "*.example.com", "www.notexample.com", false},
		{"wildcard parent", "*.example.com", "com", false},
		{"wildcard other domain", "*.example.com", "example.com.evil.net", false},

		// Double wildcard is the same as single.
		{"double wildcard subdomain", "**.example.com", "a.b.example.com", true},
		{"double wildcard matches apex", "**.example.com", "example.com", true},
		{"double wildcard lookalike", "**.example.com", "notexample.com", false},

		// Case.
		{"case pattern", "*.EXAMPLE.com", "www.example.com", true},
		{"case value", "*.example.com", "WWW.Example.COM", true},
		{"case exact", "Example.COM", "example.com", true},
		{"case apex", "*.Example.com", "EXAMPLE.COM", true},

		// Trailing dot (fully qualified form) on either side.
		{"trailing dot value", "*.example.com", "www.example.com.", true},
		{"trailing dot pattern", "*.example.com.", "www.example.com", true},
		{"trailing dot exact", "example.com.", "example.com", true},
		{"trailing dot apex", "*.example.com", "example.com.", true},

		// IDN: Unicode and punycode are the same name, both ways.
		{"idn pattern unicode, value punycode", "*.bücher.example", "shop.xn--bcher-kva.example", true},
		{"idn pattern punycode, value unicode", "*.xn--bcher-kva.example", "shop.bücher.example", true},
		{"idn exact unicode vs punycode", "bücher.example", "xn--bcher-kva.example", true},
		{"idn uppercase unicode", "*.BÜCHER.example", "shop.xn--bcher-kva.example", true},
		{"idn apex", "*.bücher.example", "xn--bcher-kva.example", true},
		{"idn different name", "*.bücher.example", "shop.bucher.example", false},

		// Non-LDH labels still compare.
		{"underscore label", "*.example.com", "_dmarc.example.com", true},

		// Patterns compared as values (CheckPatternOverlaps).
		{"pattern inside pattern", "*.example.com", "*.a.example.com", true},
		{"pattern equals pattern", "*.example.com", "*.example.com", true},
		{"double and single equivalent", "**.example.com", "*.example.com", true},
		{"single and double equivalent", "*.example.com", "**.example.com", true},
		{"exact does not contain wildcard", "example.com", "*.example.com", false},
		{"wildcard contains its exact apex", "*.example.com", "example.com", true},
		{"wildcard does not contain parent wildcard", "*.a.example.com", "*.example.com", false},

		// Degenerate input.
		{"empty value", "*.example.com", "", false},
		{"empty pattern", "", "example.com", false},
		{"bare star", "*.", "example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchDomain(tt.pattern, tt.value); got != tt.want {
				t.Errorf("matchDomain(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

// Both public entry points use the same semantics: a scope target and an
// exclusion "*.example.com" cover example.com and its subdomains; an exact
// name covers only itself.
func TestDomainWildcard_TargetsAndExclusions(t *testing.T) {
	for _, tt := range []TargetType{TargetTypeDomain, TargetTypeSubdomain, TargetTypeEmailDomain} {
		if !MatchesPattern(tt, "*.example.com", "example.com") {
			t.Errorf("target %s *.example.com leaves the apex out of scope", tt)
		}
		if !MatchesPattern(tt, "*.example.com", "api.example.com") {
			t.Errorf("target %s *.example.com misses a subdomain", tt)
		}
		if !MatchesPattern(tt, "example.com", "EXAMPLE.com.") {
			t.Errorf("target %s example.com misses its own name", tt)
		}
		if MatchesPattern(tt, "*.example.com", "notexample.com") {
			t.Errorf("target %s *.example.com covers a lookalike", tt)
		}
	}
	for _, et := range []ExclusionType{ExclusionTypeDomain, ExclusionTypeSubdomain} {
		if !MatchesExclusionPattern(et, "*.example.com", "example.com") {
			t.Errorf("exclusion %s *.example.com leaves the apex scannable", et)
		}
		if !MatchesExclusionPattern(et, "*.example.com", "api.example.com") {
			t.Errorf("exclusion %s *.example.com misses a subdomain", et)
		}
		if !MatchesExclusionPattern(et, "example.com", "example.com") {
			t.Errorf("exclusion %s example.com misses its own name", et)
		}
		if MatchesExclusionPattern(et, "example.com", "api.example.com") {
			t.Errorf("exclusion %s example.com excludes a subdomain", et)
		}
	}
}

// The subdomains-without-the-apex intent is a wildcard target plus an exact
// exclusion: the exclusion carves out the apex and nothing else.
func TestDomainWildcard_ExclusionCarvesOutApex(t *testing.T) {
	inScope := func(v string) bool {
		return MatchesPattern(TargetTypeDomain, "*.example.com", v) &&
			!MatchesExclusionPattern(ExclusionTypeDomain, "example.com", v)
	}
	if inScope("example.com") {
		t.Error("the apex is in scope although an exact exclusion names it")
	}
	for _, v := range []string{"www.example.com", "a.b.example.com"} {
		if !inScope(v) {
			t.Errorf("%s fell out of scope; the apex exclusion must not cover subdomains", v)
		}
	}
}
