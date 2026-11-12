package scope

// Label-boundary vectors for the one domain matcher, across every
// spelling a target arrives in. Scope entries and exclusions share it, so
// a lookalike name is never inside a root and an exclusion of one host
// never removes a sibling.

import "testing"

func TestAuthorityForms_LabelBoundary(t *testing.T) {
	covered := func(pattern, target string) bool {
		for _, f := range AuthorityForms(target) {
			if MatchesPattern(TargetTypeDomain, pattern, f) {
				return true
			}
		}
		return false
	}
	cases := []struct {
		pattern, target string
		want            bool
	}{
		// inside the root, in every form
		{"example.com", "example.com", true},
		{"example.com", "EXAMPLE.com.", true},
		{"example.com", "example.com:8443", true},
		{"example.com", "https://example.com/x", true},
		{"example.com", "https://example.com.:8443/x", true},
		{"*.example.com", "app.example.com:443", true},
		{"*.example.com", "HTTP://App.Example.COM./", true},
		{"*.example.com", "example.com:22", true},
		{"*.example.com", "https://xn--bcher-kva.example.com/", true},
		{"*.bücher.example", "https://shop.xn--bcher-kva.example:8443/", true},
		{"*.xn--bcher-kva.example", "shop.bücher.example:443", true},
		// lookalikes and suffix tricks, every form
		{"example.com", "notexample.com", false},
		{"example.com", "notexample.com:443", false},
		{"example.com", "https://notexample.com/", false},
		{"example.com", "example.com.evil.test", false},
		{"example.com", "https://example.com.evil.test:8443/", false},
		{"example.com", "example.com@evil.test", false},
		{"example.com", "https://example.com@evil.test/", false},
		{"example.com", "https://evil.test/?h=example.com", false},
		{"example.com", "app.example.com", false},
		{"*.example.com", "notexample.com", false},
		{"*.example.com", "evil-example.com:443", false},
		{"*.example.com", "app.example.com.evil.test", false},
		{"*.example.com", "https://app.example.com.evil.test/", false},
		{"*.example.com", "https://user:pw@app.example.com.evil.test/", false},
		{"*.example.com", "example.com.", true},
		{"*.example.com", "com", false},
		{"*.bücher.example", "shop.xn--bcher-kvb.example", false},
	}
	for _, c := range cases {
		if got := covered(c.pattern, c.target); got != c.want {
			t.Errorf("entry %q vs target %q: got %v, want %v", c.pattern, c.target, got, c.want)
		}
	}
}

// An exclusion of one host removes that host (and, as a wildcard, what is
// below it), never a sibling whose name only starts the same way.
func TestExclusionForms_LabelBoundary(t *testing.T) {
	excluded := func(pattern, target string) bool {
		for _, f := range ExclusionForms(target) {
			if matchDomain(pattern, f) {
				return true
			}
		}
		return false
	}
	cases := []struct {
		pattern, target string
		want            bool
	}{
		{"dev.example.com", "dev.example.com", true},
		{"dev.example.com", "DEV.example.com.", true},
		{"dev.example.com", "dev.example.com:8080", true},
		{"dev.example.com", "https://dev.example.com/x", true},
		{"dev.example.com", "devops.example.com", false},
		{"dev.example.com", "mydev.example.com", false},
		{"dev.example.com", "dev.example.com.evil.test", false},
		{"dev.example.com", "https://devops.example.com:8443/", false},
		{"dev.example.com", "example.com", false},
		{"dev.example.com", "x.dev.example.com", false},
		{"*.dev.example.com", "x.dev.example.com:443", true},
		{"*.dev.example.com", "dev.example.com", true},
		{"*.dev.example.com", "devops.example.com", false},
		{"*.dev.example.com", "notdev.example.com", false},
		{"*.dev.example.com", "x.dev.example.com.evil.test", false},
	}
	for _, c := range cases {
		if got := excluded(c.pattern, c.target); got != c.want {
			t.Errorf("exclusion %q vs target %q: got %v, want %v", c.pattern, c.target, got, c.want)
		}
	}
}
