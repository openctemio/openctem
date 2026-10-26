package easm

import (
	"net/netip"
	"testing"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
)

// Review by rule never offers a range rule for a published CDN edge
// address, even before enrichment recorded the address's network: one
// "accept rule" would put shared provider space in scope.
func TestGroupAddress_EdgeRangeNeverGrouped(t *testing.T) {
	s := &RuleService{guardrails: scopedom.DefaultGuardrails()}
	for _, ip := range []string{"104.16.5.7", "2606:4700::6810:1", "::ffff:104.16.5.7"} {
		g := &grouping{byPattern: map[string]*RuleSuggestion{}, blocked: map[string]string{}}
		s.groupAddress(g, ReviewItem{Name: ip}, netip.MustParseAddr(ip), nil)
		if len(g.byPattern) != 0 {
			t.Errorf("%s: rule suggested %v, want none", ip, g.byPattern)
		}
		if len(g.individual) != 1 || !g.individual[0].SharedIP {
			t.Errorf("%s: individual %+v, want one shared item", ip, g.individual)
		}
	}
	// An ordinary address still groups under its /24.
	g := &grouping{byPattern: map[string]*RuleSuggestion{}, blocked: map[string]string{}}
	s.groupAddress(g, ReviewItem{Name: "198.51.100.7"}, netip.MustParseAddr("198.51.100.7"), nil)
	if _, ok := g.byPattern["198.51.100.0/24"]; !ok {
		t.Errorf("ordinary address not grouped: %v", g.byPattern)
	}
}
