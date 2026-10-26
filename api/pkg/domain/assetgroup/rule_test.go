package assetgroup

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestDomainMatches_LabelBoundary(t *testing.T) {
	sub := DomainCondition{Name: "pti.com.vn", Subdomains: true}
	exact := DomainCondition{Name: "pti.com.vn"}
	cases := []struct {
		name     string
		cond     DomainCondition
		asset    string
		expected bool
	}{
		{"apex with subdomains", sub, "pti.com.vn", true},
		{"subdomain", sub, "www.pti.com.vn", true},
		{"deep subdomain", sub, "a.b.c.pti.com.vn", true},
		{"upper case", sub, "WWW.PTI.COM.VN", true},
		{"look-alike prefix is not a subdomain", sub, "evilpti.com.vn", false},
		{"look-alike prefix with dash", sub, "evil-pti.com.vn", false},
		{"domain used as a label of another", sub, "pti.com.vn.evil.com", false},
		{"parent is not below", sub, "com.vn", false},
		{"sibling", sub, "other.com.vn", false},
		{"exact apex", exact, "pti.com.vn", true},
		{"exact does not take subdomains", exact, "www.pti.com.vn", false},
		{"idn matches its punycode form", DomainCondition{Name: "xn--bcher-kva.de", Subdomains: true}, "www.bücher.de", true},
	}
	for _, c := range cases {
		if got := DomainMatches(c.cond, c.asset); got != c.expected {
			t.Errorf("%s: DomainMatches(%+v, %q) = %v, want %v", c.name, c.cond, c.asset, got, c.expected)
		}
	}
}

func TestNormalizeDomain(t *testing.T) {
	ok := []struct {
		in, name string
		wildcard bool
	}{
		{"pti.com.vn", "pti.com.vn", false},
		{"  PTI.com.VN.  ", "pti.com.vn", false},
		{"*.pti.com.vn", "pti.com.vn", true},
		{"bücher.de", "xn--bcher-kva.de", false},
		{"*.BÜCHER.de", "xn--bcher-kva.de", true},
		{"_dmarc.example.com", "_dmarc.example.com", false},
	}
	for _, c := range ok {
		name, wc, err := NormalizeDomain(c.in)
		if err != nil || name != c.name || wc != c.wildcard {
			t.Errorf("NormalizeDomain(%q) = %q, %v, %v; want %q, %v", c.in, name, wc, err, c.name, c.wildcard)
		}
	}
	bad := []string{
		"", "   ", "com", "*.com", "*", "a*.example.com", "ex*mple.com", "**.example.com",
		"http://example.com", "example.com/path", "example.com:443", "user@example.com",
		"10.0.0.1", "2001:db8::1", "exa mple.com", "example.com\r\nX: y", "example.com\x00",
		"-bad.example.com", "bad-.example.com", "a..example.com", strings.Repeat("a", 64) + ".example.com",
		strings.Repeat("a.", 130) + "com",
	}
	for _, in := range bad {
		if _, _, err := NormalizeDomain(in); err == nil {
			t.Errorf("NormalizeDomain(%q) accepted", in)
		} else if !errors.Is(err, ErrInvalidRule) || !errors.Is(err, shared.ErrValidation) {
			t.Errorf("NormalizeDomain(%q) error %v is not a validation error", in, err)
		}
	}
}

func TestParseRule(t *testing.T) {
	r, err := ParseRule([]byte(`{"v":1,"filter":{"types":["domain"],"tags":["prod"]},"domains":[{"name":"*.PTI.com.vn"},{"name":"pti.com.vn","subdomains":false}],"include_related":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != RuleVersion || len(r.Domains) != 1 || r.Domains[0].Name != "pti.com.vn" || !r.Domains[0].Subdomains {
		t.Fatalf("domains not normalised and merged: %+v", r.Domains)
	}
	b, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParseRule(b)
	if err != nil || again.Domains[0] != r.Domains[0] || !again.IncludeRelated {
		t.Fatalf("round trip: %+v %v", again, err)
	}

	// A version is optional in the request and stored as the current one.
	if r, err := ParseRule([]byte(`{"filter":{"search":"x"}}`)); err != nil || r.Version != RuleVersion {
		t.Fatalf("missing version: %+v %v", r, err)
	}

	bad := map[string]string{
		"unknown field":      `{"v":1,"filter":{"types":["domain"]},"sql":"1=1"}`,
		"unknown filter key": `{"v":1,"filter":{"types":["domain"],"id":"x"}}`,
		"future version":     `{"v":2,"filter":{"types":["domain"]}}`,
		"no condition":       `{"v":1,"filter":{}}`,
		"empty object":       `{}`,
		"not an object":      `[1]`,
		"trailing data":      `{"v":1,"filter":{"types":["domain"]}} {}`,
		"wrong type":         `{"v":1,"filter":{"types":"domain"}}`,
		"bad domain":         `{"v":1,"domains":[{"name":"http://evil"}]}`,
		"bad cidr":           `{"v":1,"filter":{"in_cidr":["10.0.0.0/33"]}}`,
		"bad covered_by":     `{"v":1,"covered_by":["not-a-uuid"]}`,
		"bad tags mode":      `{"v":1,"filter":{"tags":["a"],"tags_mode":"some"}}`,
		"too many domains":   `{"v":1,"domains":[` + strings.TrimSuffix(strings.Repeat(`{"name":"a.example.com"},`, 1), ",") + manyDomains(MaxRuleDomains+1) + `]}`,
	}
	for name, doc := range bad {
		if _, err := ParseRule([]byte(doc)); err == nil {
			t.Errorf("%s: accepted %s", name, doc)
		} else if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: %v is not a validation error", name, err)
		}
	}
	if _, err := ParseRule([]byte(`{"v":1,"filter":{"search":"` + strings.Repeat("x", MaxRuleBytes) + `"}}`)); err == nil {
		t.Error("an oversized rule was accepted")
	}
}

func manyDomains(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(`,{"name":"d` + string(rune('a'+i%26)) + string(rune('a'+i/26)) + `.example.com"}`)
	}
	return b.String()
}
