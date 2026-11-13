package scope

// A domain entry authorizes host names only, and only provably internal
// targets skip the scope entry check. These rows are the scope bypass and
// misclassification cases found in the 2026-10 CTEM review.

import "testing"

func TestDomainEntry_NeverMatchesURLText(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"*.scoped.example", "http://other.test/?q=.scoped.example", false},
		{"*.scoped.example", "https://other.test/#.scoped.example", false},
		{"*.scoped.example", "http://other.test/a/b.scoped.example", false},
		{"*.scoped.example", "http://user@other.test/x.scoped.example", false},
		{"*.scoped.example", "other.test:443/.scoped.example", false},
		{"*.scoped.example", "other.test .scoped.example", false},
		{"*.scoped.example", "other.test%2f.scoped.example", false},
		// fullwidth solidus maps to "/" under IDNA lookup mapping
		{"*.scoped.example", "other.test／.scoped.example", false},
		// host names still match
		{"*.scoped.example", "app.scoped.example", true},
		{"*.scoped.example", "APP.Scoped.Example.", true},
		{"*.scoped.example", "scoped.example", true},
		{"scoped.example", "scoped.example", true},
	}
	for _, c := range cases {
		for _, typ := range []TargetType{TargetTypeDomain, TargetTypeSubdomain, TargetTypeHost} {
			if got := MatchesPattern(typ, c.pattern, c.value); got != c.want {
				t.Errorf("%s %q vs %q: got %v, want %v", typ, c.pattern, c.value, got, c.want)
			}
		}
	}
}

func TestAuthorityForms_URLMatchesOnlyThroughItsHost(t *testing.T) {
	// A URL target is authorized by its host: the host form matches, the
	// raw URL text never does.
	covered := func(target string) bool {
		for _, f := range AuthorityForms(target) {
			if MatchesPattern(TargetTypeDomain, "*.scoped.example", f) {
				return true
			}
		}
		return false
	}
	if covered("http://other.test/?q=.scoped.example") {
		t.Fatal("URL on another host with the scoped name in its query is covered")
	}
	if !covered("https://app.scoped.example:8443/login?next=/") {
		t.Fatal("URL on a scoped host is not covered")
	}
}

func TestNeedsAuthority_Table(t *testing.T) {
	cases := []struct {
		target string
		want   bool
	}{
		{"10.0.0.5", false},
		{"10.1.0.0/16", false},
		{"192.168.1.0/24", false},
		{"::1", false},
		{"fd00::/8", false},
		{"intranet.local", false},
		{"8.8.8.8", true},
		{"example.com", true},
		{"https://example.com/x", true},
		// a prefix is internal only when all of it is
		{"0.0.0.0/0", true},
		{"10.0.0.0/1", true},
		{"::/0", true},
		{"::1/1", true},
		{"172.16.0.0/11", true},
		{"::ffff:10.0.0.0/100", true},
		{"::ffff:10.0.0.0/104", false},
		{"::ffff:10.0.0.0/112", false},
		// addresses in decimal or hex notation
		{"2852039166", true},
		{"http://2852039166/", true},
		{"0xa9fea9fe", true},
		{"http://0xa9fea9fe/latest", true},
		// text that names no host
		{"group/project", false},
	}
	for _, c := range cases {
		if got := NeedsAuthority(c.target); got != c.want {
			t.Errorf("NeedsAuthority(%q) = %v, want %v", c.target, got, c.want)
		}
	}
}

func TestIPAddressEntry_AnySpelling(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"2001:db8::1", "2001:DB8::1", true},
		{"2001:DB8:0::1", "2001:db8::1", true},
		{"10.0.0.5", "::ffff:10.0.0.5", true},
		{"10.0.0.5", "10.0.0.5", true},
		{"10.0.0.5", "10.0.0.6", false},
		{"10.0.0.5", "10.0.0.0/24", false},
		{"not-an-ip", "not-an-ip", false},
	}
	for _, c := range cases {
		if got := MatchesPattern(TargetTypeIPAddress, c.pattern, c.value); got != c.want {
			t.Errorf("ip %q vs %q: got %v, want %v", c.pattern, c.value, got, c.want)
		}
	}
}
