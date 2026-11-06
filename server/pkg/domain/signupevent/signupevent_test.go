package signupevent

import "testing"

func TestEmailDomainKeepsOnlyTheRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"a.b@mail.example.co.uk": "example.co.uk",
		"Bob@Example.COM":        "example.com",
		"x@sub.example.com.":     "example.com",
		"no-at-sign":             "",
		"trailing@":              "",
		"ip@[192.0.2.1]":         "",
		"tld@com":                "",
	}
	for in, want := range cases {
		if got := EmailDomain(in); got != want {
			t.Errorf("EmailDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIPPrefixTruncatesToTheNetwork(t *testing.T) {
	cases := map[string]string{
		"198.51.100.77":           "198.51.100.0/24",
		"198.51.100.77:4431":      "198.51.100.0/24",
		"::ffff:198.51.100.7":     "198.51.100.0/24",
		"2001:db8:abcd:12::1":     "2001:db8:abcd::/48",
		"[2001:db8:abcd:12::1]:1": "2001:db8:abcd::/48",
		"not an ip":               "",
		"":                        "",
	}
	for in, want := range cases {
		if got := IPPrefix(in); got != want {
			t.Errorf("IPPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOnlySelfServiceSourcesCarryAnAddress(t *testing.T) {
	for _, s := range []Source{SourcePassword, SourceInvitation, SourceOAuth, SourceSSO, SourceSelfService, SourcePublic} {
		if !s.SelfService() {
			t.Errorf("%s must count as self-service", s)
		}
	}
	for _, s := range []Source{SourceConsole, SourceAccessRequest, SourceControlPlane} {
		if s.SelfService() {
			t.Errorf("%s is an operator path and must not record the operator's network", s)
		}
	}
}

func TestBurstThresholdsValidate(t *testing.T) {
	if err := DefaultBurstThresholds().Validate(); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	n := BurstThresholds{PerIPPrefix: 1, WindowMinutes: 60,
		IgnoredDomains: []string{" Gmail.com ", "@gmail.com", "", "example.org."}}.Normalize()
	if len(n.IgnoredDomains) != 2 || n.IgnoredDomains[0] != "example.org" || n.IgnoredDomains[1] != "gmail.com" {
		t.Fatalf("normalize: %v", n.IgnoredDomains)
	}
	if !n.Ignores("gmail.com") || n.Ignores("example.com") {
		t.Fatal("Ignores")
	}
	bad := []BurstThresholds{
		{PerIPPrefix: -1, WindowMinutes: 60},
		{PerEmailDomain: MaxThreshold + 1, WindowMinutes: 60},
		{WindowMinutes: MinWindowMinutes - 1},
		{WindowMinutes: MaxWindowMinutes + 1},
		{WindowMinutes: 60, IgnoredDomains: []string{"not a domain"}},
		{WindowMinutes: 60, IgnoredDomains: make([]string, MaxIgnoredDomains+1)},
	}
	for i, b := range bad {
		if err := b.Validate(); err == nil {
			t.Errorf("case %d must be refused: %+v", i, b)
		}
	}
}
