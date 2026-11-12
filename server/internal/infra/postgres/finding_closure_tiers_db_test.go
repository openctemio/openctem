package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// FindingRiskTiers reads severity, priority class and KEV in one query and
// is tenant-scoped: another tenant's finding ids return nothing.
func TestFindingRiskTiers_DB(t *testing.T) {
	f := newCoverageFixture(t)
	other := newCoverageFixture(t)
	repo := NewFindingRepository(&DB{DB: f.db})
	ctx := context.Background()

	high := f.finding(t, f.host, "nuclei", "", nil) // severity high
	medium := f.finding(t, f.host, "nuclei", "", nil)
	f.exec(t, `UPDATE findings SET severity = 'medium' WHERE id = $1`, medium)
	critical := f.finding(t, f.host, "nuclei", "", nil)
	f.exec(t, `UPDATE findings SET severity = 'critical' WHERE id = $1`, critical)
	kev := f.finding(t, f.host, "nuclei", "", nil)
	f.exec(t, `UPDATE findings SET severity = 'low', is_in_kev = true WHERE id = $1`, kev)
	p0 := f.finding(t, f.host, "nuclei", "", nil)
	f.exec(t, `UPDATE findings SET severity = 'medium', priority_class = 'P0' WHERE id = $1`, p0)
	foreign := other.finding(t, other.host, "nuclei", "", nil)
	f.exec(t, `UPDATE findings SET severity = 'critical' WHERE id = $1`, foreign)

	got, err := repo.FindingRiskTiers(ctx, f.tenant, []shared.ID{high, medium, critical, kev, p0, foreign})
	if err != nil {
		t.Fatal(err)
	}
	want := map[shared.ID]vulnerability.RiskTier{
		high: vulnerability.RiskTierHigh, medium: vulnerability.RiskTierStandard,
		critical: vulnerability.RiskTierCritical, kev: vulnerability.RiskTierCritical, p0: vulnerability.RiskTierCritical,
	}
	if len(got) != len(want) {
		t.Fatalf("tiers = %v, want %v (another tenant's id must be absent)", got, want)
	}
	for id, tier := range want {
		if got[id] != tier {
			t.Errorf("tier of %s = %q, want %q", id, got[id], tier)
		}
	}
	if _, ok := got[foreign]; ok {
		t.Fatal("another tenant's finding returned")
	}

	// Asked as the other tenant, this tenant's ids return nothing.
	cross, err := repo.FindingRiskTiers(ctx, other.tenant, []shared.ID{high, critical})
	if err != nil || len(cross) != 0 {
		t.Fatalf("cross-tenant read = %v, %v; want empty", cross, err)
	}
	if empty, err := repo.FindingRiskTiers(ctx, f.tenant, nil); err != nil || len(empty) != 0 {
		t.Fatalf("no ids = %v, %v", empty, err)
	}
}
