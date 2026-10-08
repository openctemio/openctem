package easm

import (
	"net/netip"
	"slices"
	"testing"
)

func TestDomainPatterns(t *testing.T) {
	cases := map[string][]string{
		"a.dev.example.com.au": {"*.dev.example.com.au", "*.example.com.au"},
		"example.com.au":       {"*.example.com.au"},
		"x.y.example.co.uk":    {"*.y.example.co.uk", "*.example.co.uk"},
		"com.vn":               nil, // a public suffix has no registrable domain
	}
	for host, want := range cases {
		if got := domainPatterns(host); !slices.Equal(got, want) {
			t.Errorf("domainPatterns(%s) = %v, want %v", host, got, want)
		}
	}
}

func TestIPPattern(t *testing.T) {
	if got := ipPattern(netip.MustParseAddr("203.0.113.77")); got != "203.0.113.0/24" {
		t.Errorf("v4 = %s", got)
	}
	if got := ipPattern(netip.MustParseAddr("2001:db8:1:2::5")); got != "2001:db8:1::/48" {
		t.Errorf("v6 = %s", got)
	}
}

func TestSharedAddressAndStrength(t *testing.T) {
	if ok, _ := sharedAddress(map[string]any{"asn_org": "AMAZON-02"}); !ok {
		t.Error("an Amazon address is shared provider space")
	}
	if ok, _ := sharedAddress(map[string]any{"cdn": "cloudflare"}); !ok {
		t.Error("a CDN-flagged address is shared")
	}
	if ok, _ := sharedAddress(map[string]any{"asn_org": "EXAMPLECO-AS-VN"}); ok {
		t.Error("an organization's own allocation is not shared")
	}
	hints := evidenceHints([]ReviewEvidence{{Rule: "fqdn_under_asserted_root", Observed: map[string]any{"root": "example.com.au", "root_origin": "easm_seed"}}})
	if len(hints) != 1 || hints[0].Kind != "discovering_easm_seed" || strengthOf(hints) != StrengthMedium {
		t.Errorf("seed hint = %+v %s", hints, strengthOf(hints))
	}
	if strengthOf([]RuleHint{{Kind: "verified_domain", Value: "x"}}) != StrengthStrong || strengthOf(nil) != StrengthWeak {
		t.Error("strength order")
	}
}
