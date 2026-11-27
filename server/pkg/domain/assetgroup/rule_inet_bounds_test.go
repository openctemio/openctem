package assetgroup

import (
	"strings"
	"testing"
)

// A smart group rule a person sends has the same range width bound as the
// assets ip filter it saves: 0.0.0.0/0 and other ranges wider than /8 (IPv4)
// or /32 (IPv6) are refused, narrower ones are kept. A rule stored before the
// bound still normalizes (it keeps loading and evaluating).
func TestRuleInCIDR_InputRefusesTooWideRanges(t *testing.T) {
	for _, c := range []string{"0.0.0.0/0", "::/0", "10.0.0.0/7", "2001:db8::/31"} {
		r := Rule{Version: RuleVersion, Filter: RuleFilter{InCIDR: []string{c}}}
		if err := r.Normalize(); err != nil {
			t.Errorf("in_cidr %s: a stored rule must still normalize: %v", c, err)
		}
		if err := r.CheckInputBounds(); err == nil || !strings.Contains(err.Error(), "/8 (IPv4) or /32 (IPv6)") {
			t.Errorf("in_cidr %s: err = %v, want the width bound named", c, err)
		}
	}
	r := Rule{Version: RuleVersion, Filter: RuleFilter{InCIDR: []string{"10.0.0.0/8", "2001:db8::/32"}}}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	if err := r.CheckInputBounds(); err != nil {
		t.Errorf("in_cidr within the bound: %v", err)
	}
}
