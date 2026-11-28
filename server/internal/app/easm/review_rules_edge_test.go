package easm

import (
	"net/netip"
	"testing"

	scopedom "github.com/openctemio/openctem/server/pkg/domain/scope"
)

// Review by rule never offers a range rule for a published CDN edge
// address, even before enrichment recorded the address's network: one
// "accept rule" would put shared provider space in scope.
func TestGroupAddress_EdgeRangeNeverGrouped(t *testing.T) {
	s := &RuleService{guardrails: scopedom.DefaultGuardrails()}
	for _, ip := range []string{"104.16.5.7", "2606:4700::6810:1", "::ffff:104.16.5.7"} {
		g := &grouping{byPattern: map[string]*RuleSuggestion{}, blocked: map[string]string{}}
		s.groupAddress(g, ReviewItem{Name: ip}, netip.MustParseAddr(ip), ipPattern(netip.MustParseAddr(ip).Unmap()), nil)
		if len(g.byPattern) != 0 {
			t.Errorf("%s: rule suggested %v, want none", ip, g.byPattern)
		}
		if len(g.individual) != 1 || !g.individual[0].SharedIP {
			t.Errorf("%s: individual %+v, want one shared item", ip, g.individual)
		}
	}
	// An ordinary address still groups under its /24.
	g := &grouping{byPattern: map[string]*RuleSuggestion{}, blocked: map[string]string{}}
	s.groupAddress(g, ReviewItem{Name: "198.51.100.7"}, netip.MustParseAddr("198.51.100.7"), "198.51.100.0/24", nil)
	if _, ok := g.byPattern["198.51.100.0/24"]; !ok {
		t.Errorf("ordinary address not grouped: %v", g.byPattern)
	}
}

// A range item is grouped as a range and never read as a domain; a name that
// is not a host name (an app id with its platform, a masked address) gives
// no domain wildcard. Seen on the review page: "*.0.113.0/24" for
// 203.0.113.0/24, "*.20.1.0", "*.example.holdings.shop (android)".
func TestRuleSuggestions_NoMalformedPatterns(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.0/24": "203.0.113.0/24",
		"10.20.1.0/25":   "10.20.1.0/24",
		"10.0.0.0/16":    "10.0.0.0/16",
		"2001:db8::/32":  "2001:db8::/32",
		"2001:db8::/64":  "2001:db8::/48",
	} {
		if got := rangePattern(netip.MustParsePrefix(in)); got != want {
			t.Errorf("rangePattern(%s) = %s, want %s", in, got, want)
		}
	}
	for _, bad := range []string{"", "0.113.0/24", "10.20.1.0", "shop.holdings.example (android)", "a b.example.com", "203.0.113.0/24"} {
		if suggestableDomain(bad) {
			t.Errorf("suggestableDomain(%q) = true, want false", bad)
		}
	}
	for _, ok := range []string{"www.example.com", "api.example.co.uk", "x1.example.io"} {
		if !suggestableDomain(ok) {
			t.Errorf("suggestableDomain(%q) = false, want true", ok)
		}
	}
}
