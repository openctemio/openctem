package scope

import (
	"context"
	"testing"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A scope exclusion names a host; a scan target may name the same host as a
// URL or with a port. Reproduced live against develop (2026-10-01): with a
// domain exclusion "excluded.example.net", a scan of
// "https://excluded.example.net/path" was dispatched to the sensor — the
// exclusion only compared the raw target string.

func newTypedExclusion(t *testing.T, tenantID shared.ID, typ scopedom.ExclusionType, pattern string) *scopedom.Exclusion {
	t.Helper()
	e, err := scopedom.NewExclusion(tenantID, typ, pattern, "test exclusion", nil, "tester")
	if err != nil {
		t.Fatalf("NewExclusion(%s, %s): %v", typ, pattern, err)
	}
	return e
}

func TestExcludedTargets_MatchesTheHostOfURLAndHostPortTargets(t *testing.T) {
	tenantID := shared.NewID()
	svc := newFilterService(&fakeExclusionRepo{active: []*scopedom.Exclusion{
		newTypedExclusion(t, tenantID, scopedom.ExclusionTypeDomain, "excluded.example.net"),
		newTypedExclusion(t, tenantID, scopedom.ExclusionTypeIPAddress, "203.0.113.7"),
		newTypedExclusion(t, tenantID, scopedom.ExclusionTypeCIDR, "198.51.100.0/24"),
	}})

	excludedTargets := []string{
		"https://excluded.example.net/path",
		"http://EXCLUDED.example.net:8080",
		"excluded.example.net:443",
		"http://203.0.113.7/admin",
		"203.0.113.7:22",
		"https://198.51.100.20:8443/",
	}
	keptTargets := []string{
		"https://other.example.net/excluded.example.net",
		"https://notexcluded.example.net",
		"http://203.0.113.70/",
	}

	candidates := make([]ExclusionCandidate, 0, len(excludedTargets)+len(keptTargets))
	ids := map[shared.ID]string{}
	for _, v := range append(append([]string{}, excludedTargets...), keptTargets...) {
		id := shared.NewID()
		ids[id] = v
		candidates = append(candidates, ExclusionCandidate{ID: id, Values: []string{v}})
	}

	excluded, err := svc.ExcludedTargets(context.Background(), tenantID.String(), candidates)
	if err != nil {
		t.Fatalf("ExcludedTargets: %v", err)
	}

	want := map[string]bool{}
	for _, v := range excludedTargets {
		want[v] = true
	}
	for id, v := range ids {
		if excluded[id] != want[v] {
			t.Errorf("target %q excluded = %v, want %v", v, excluded[id], want[v])
		}
	}
}
