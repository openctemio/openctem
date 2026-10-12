package scope

import (
	"context"
	"testing"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A scan target can be a whole network. Before this test, an exclusion was
// only ever compared against single addresses, so a scan of "10.20.0.0/16"
// with "10.20.5.0/24" excluded was dispatched in full and swept the excluded
// /24; an excluded address inside a target range was missed the same way.
// Any overlap now skips the target (the scanner is handed the range as written).
func TestExcludedTargets_NetworkTargetsOverlappingAnExclusionAreSkipped(t *testing.T) {
	tenantID := shared.NewID()
	svc := newFilterService(&fakeExclusionRepo{active: []*scopedom.Exclusion{
		newTypedExclusion(t, tenantID, scopedom.ExclusionTypeCIDR, "10.20.5.0/24"),
		newTypedExclusion(t, tenantID, scopedom.ExclusionTypeIPAddress, "192.0.2.10"),
		newTypedExclusion(t, tenantID, scopedom.ExclusionTypeIPRange, "198.51.100.250-198.51.101.5"),
		newTypedExclusion(t, tenantID, scopedom.ExclusionTypeCIDR, "2001:db8:5::/48"),
	}})

	cases := map[string]bool{
		"10.20.0.0/16":    true,  // contains the excluded /24
		"10.20.5.128/25":  true,  // inside the excluded /24
		"10.21.0.0/16":    false, // disjoint
		"192.0.2.0/24":    true,  // contains the excluded address
		"192.0.3.0/24":    false,
		"198.51.101.0/24": true, // overlaps the excluded range
		"2001:db8::/32":   true, // contains the excluded /48
		"2001:db9::/32":   false,
	}

	candidates := make([]ExclusionCandidate, 0, len(cases))
	ids := map[shared.ID]string{}
	for v := range cases {
		id := shared.NewID()
		ids[id] = v
		candidates = append(candidates, ExclusionCandidate{ID: id, Values: []string{v}})
	}
	excluded, err := svc.ExcludedTargets(context.Background(), tenantID.String(), candidates)
	if err != nil {
		t.Fatalf("ExcludedTargets: %v", err)
	}
	for id, v := range ids {
		if excluded[id] != cases[v] {
			t.Errorf("target %q excluded = %v, want %v", v, excluded[id], cases[v])
		}
	}
}
