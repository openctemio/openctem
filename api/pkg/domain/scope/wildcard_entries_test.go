package scope

import (
	"errors"
	"testing"
)

// The types that have no matcher take no wildcard, so "*" never reads as
// "every host and address" (scope entries of these types used to fall back
// to wildcard text matching).
func TestValidatePatternRefusesWildcardForEveryType(t *testing.T) {
	for _, tt := range AllTargetTypes() {
		for _, p := range []string{"*", "*.com", "*com", "**", "*.*"} {
			err := ValidatePattern(tt, p)
			if err == nil && p == "*.com" && tt.AuthorizesProbes() {
				// A well-formed domain wildcard: the platform guardrail
				// (public suffix) refuses it.
				err = DefaultGuardrails().CheckPattern(tt, p)
			}
			if err == nil {
				t.Errorf("%s: pattern %q accepted", tt, p)
			}
		}
	}
	for _, tt := range []TargetType{TargetTypeCertificate, TargetTypeContainer, TargetTypeDatabase,
		TargetTypeMobileApp, TargetTypeCloudResource, TargetTypeNetwork} {
		err := ValidatePattern(tt, "sha256:ab*")
		if !errors.Is(err, ErrWildcardNotAllowed) {
			t.Errorf("%s: a wildcard inside a pattern gave %v", tt, err)
		}
	}
}

func TestURLEntryNeedsSchemeAndConcreteHost(t *testing.T) {
	for _, p := range []string{"*", "*.example.com", "https://*", "https://*.example.com", "http://*/x",
		"https://", "https:///x", "example.com", "https://user@example.com/", "https://example.com?x=1"} {
		for _, tt := range []TargetType{TargetTypeURL, TargetTypeAPI, TargetTypeWebsite} {
			if err := ValidatePattern(tt, p); err == nil {
				t.Errorf("%s: %q accepted", tt, p)
			}
		}
	}
	for _, p := range []string{"*://app.example.com", "https://app.example.com", "http://app.example.com:8080/api/*", "https://203.0.113.5/", "https://[2001:db8::1]:8443/x"} {
		if err := ValidatePattern(TargetTypeURL, p); err != nil {
			t.Errorf("%q refused: %v", p, err)
		}
	}
}

func TestHostEntry(t *testing.T) {
	for _, p := range []string{"*", "*.*", "a*.example.com", "*.example.*", "0.0.0.0/0", "10.0.0.0/8", "1.0.0.0-223.255.255.255"} {
		if err := ValidatePattern(TargetTypeHost, p); err == nil {
			t.Errorf("host %q accepted", p)
		}
	}
	for _, p := range []string{"app.example.com", "*.example.com", "203.0.113.5"} {
		if err := ValidatePattern(TargetTypeHost, p); err != nil {
			t.Errorf("host %q refused: %v", p, err)
		}
	}
	if !MatchesPattern(TargetTypeHost, "*.example.com", "a.b.example.com") || MatchesPattern(TargetTypeHost, "*.example.com", "example.org") {
		t.Error("host wildcard must match names under the domain only")
	}
	if MatchesPattern(TargetTypeHost, "203.0.113.5", "203.0.113.6") || !MatchesPattern(TargetTypeHost, "203.0.113.5", "203.0.113.5") {
		t.Error("host address must match itself only")
	}
}

// A stored row of a type without a matcher, or with a wildcard host, covers
// nothing, whatever its pattern says.
func TestEntryMatchesIgnoresTypesWithoutMatcher(t *testing.T) {
	victims := []string{"victim.example", "203.0.113.9", "https://victim.example/", "203.0.113.9:443"}
	rows := []struct {
		tt      TargetType
		pattern string
	}{
		{TargetTypeCertificate, "*"}, {TargetTypeContainer, "*"}, {TargetTypeDatabase, "*"},
		{TargetTypeMobileApp, "*"}, {TargetTypeCloudResource, "*"}, {TargetTypeNetwork, "*"},
		{TargetTypeNetwork, "victim.example"}, {TargetTypeCertificate, "victim.example"},
		{TargetTypeURL, "*"}, {TargetTypeURL, "https://*"}, {TargetTypeWebsite, "https://*/"},
		{TargetTypeAPI, "*"}, {TargetTypeHost, "*"},
		{TargetTypeProject, "*"}, {TargetTypeProject, "github.com/*"}, {TargetTypeCloudAccount, "*"},
	}
	for _, r := range rows {
		for _, v := range victims {
			if EntryMatches(r.tt, r.pattern, Constraint{}, v) {
				t.Errorf("%s %q covers %q", r.tt, r.pattern, v)
			}
		}
	}
}

func TestProbeAuthorityTypes(t *testing.T) {
	want := map[TargetType]bool{
		TargetTypeDomain: true, TargetTypeSubdomain: true, TargetTypeEmailDomain: true,
		TargetTypeIPAddress: true, TargetTypeIPRange: true, TargetTypeCIDR: true,
		TargetTypeURL: true, TargetTypeAPI: true, TargetTypeWebsite: true,
		TargetTypeHost: true, TargetTypeRepository: true,
	}
	for _, tt := range AllTargetTypes() {
		if tt.AuthorizesProbes() != want[tt] {
			t.Errorf("%s AuthorizesProbes = %v", tt, tt.AuthorizesProbes())
		}
		if tt.Retired() && tt.AuthorizesProbes() {
			t.Errorf("%s is retired but authorizes", tt)
		}
	}
}

// Guardrails keep applying to the types that remain: public suffix, deny
// list and CIDR size.
func TestGuardrailsOnHostEntries(t *testing.T) {
	g := DefaultGuardrails()
	if err := g.CheckPattern(TargetTypeHost, "*.com"); !errors.Is(err, ErrPublicSuffix) {
		t.Errorf("host *.com: %v", err)
	}
	if err := g.CheckPattern(TargetTypeHost, "169.254.169.254"); err == nil {
		t.Error("host metadata address accepted")
	}
	if err := g.CheckPattern(TargetTypeHost, "*.example.com"); err != nil {
		t.Errorf("host *.example.com: %v", err)
	}
	if err := g.CheckPattern(TargetTypeCIDR, "0.0.0.0/0"); err == nil {
		t.Error("0.0.0.0/0 accepted")
	}
	if err := g.CheckPattern(TargetTypeDomain, "*.co.uk"); !errors.Is(err, ErrPublicSuffix) {
		t.Errorf("*.co.uk: %v", err)
	}
}

// A stored host row that is a network or a range covers nothing: those
// belong to cidr and ip_range entries.
func TestHostRowsNeverCoverNetworks(t *testing.T) {
	for _, p := range []string{"0.0.0.0/0", "203.0.113.0/24", "1.0.0.0-223.255.255.255", "::/0"} {
		for _, v := range []string{"203.0.113.9", "198.51.100.1", "victim.example"} {
			if EntryMatches(TargetTypeHost, p, Constraint{}, v) {
				t.Errorf("host %q covers %q", p, v)
			}
		}
	}
	if !EntryMatches(TargetTypeHost, "203.0.113.9", Constraint{}, "203.0.113.9") {
		t.Error("a host address must cover itself")
	}
}

// "*://host" means any scheme on that host. The star must not swallow a
// host: a value that carries the entry's text later in its path or query is
// not covered.
func TestWildSchemeURLEntryCannotCoverOtherHosts(t *testing.T) {
	const pat = "*://app.example.com"
	for _, v := range []string{
		"https://victim.example/x://app.example.com",
		"https://victim.example/x://app.example.com/",
		"https://victim.example/?u=a://app.example.com",
		"foo.bar://app.example.com",
		"app.example.com",
	} {
		if EntryMatches(TargetTypeURL, pat, Constraint{}, v) {
			t.Errorf("%q covered by %q", v, pat)
		}
	}
	for _, v := range []string{"http://app.example.com", "https://app.example.com"} {
		if !EntryMatches(TargetTypeURL, pat, Constraint{}, v) {
			t.Errorf("%q not covered by %q", v, pat)
		}
	}
	if !EntryMatches(TargetTypeURL, "*://app.example.com/*", Constraint{}, "https://app.example.com/path") {
		t.Error("wild scheme with a path star does not cover its own host")
	}
	if EntryMatches(TargetTypeURL, "*://app.example.com/*", Constraint{}, "https://victim.example/x://app.example.com/path") {
		t.Error("wild scheme with a path star covers another host")
	}
	// The path-limited form binds the value's scheme too.
	if EntryMatches(TargetTypeURL, "*://app.example.com/api/*", Constraint{}, "https://victim.example/x://app.example.com/api/a") {
		t.Error("path-limited wild scheme covers another host")
	}
	if !EntryMatches(TargetTypeURL, "*://app.example.com/api/*", Constraint{}, "https://app.example.com/api/a") {
		t.Error("path-limited wild scheme does not cover its own host")
	}
}
