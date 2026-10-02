package postgres

import (
	"math"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// These are regressions for the dead-enum-literal class: a dashboard query
// filters on a value the column's CHECK constraint can never hold, so the
// filter matches nothing and the metric reads a confident 0 instead of failing.

// assets.exposure is one of public/private/restricted/isolated/unknown. The
// data-quality scorecard filtered internet-exposed assets with
// exposure = 'internet', so "Median last-seen (internet-exposed)" was always 0.0d.
func TestDataQualityScorecard_MedianLastSeenCountsInternetExposedAssets(t *testing.T) {
	f, repo := newPMFixture(t)
	tenant := seedTestTenant(f.ctx, t, f.db)
	noise := seedTestTenant(f.ctx, t, f.db)

	seedSeen := func(tn shared.ID, exposure string, internet bool, daysAgo int) {
		id := f.asset(tn, exposure, internet, "active", f.at(-400*pmDay), nil)
		f.exec(`UPDATE assets SET last_seen = $2 WHERE id = $1`, id.String(), f.at(-time.Duration(daysAgo)*pmDay))
	}
	// Internet-exposed: public at 10d and 30d, internet-accessible (exposure
	// still unknown) at 20d -> median 20d.
	seedSeen(tenant, "public", false, 10)
	seedSeen(tenant, "public", false, 30)
	seedSeen(tenant, "unknown", true, 20)
	// Not internet-exposed: must not move the median.
	seedSeen(tenant, "private", false, 300)
	seedSeen(tenant, "restricted", false, 200)
	// Other tenant: must not leak.
	seedSeen(noise, "public", false, 365)

	sc, err := repo.GetDataQualityScorecard(f.ctx, tenant)
	if err != nil {
		t.Fatalf("GetDataQualityScorecard: %v", err)
	}
	if math.Abs(sc.MedianLastSeenDays-20) > 0.01 {
		t.Fatalf("MedianLastSeenDays = %.3f, want 20 (median of internet-exposed assets)", sc.MedianLastSeenDays)
	}
}

// asset_components.dependency_type is direct/transitive/dev/optional/peer/build;
// deprecated/end_of_life live in asset_components.status. Both component stats
// queries filtered dependency_type for them, so "outdated" was always 0.
func TestComponentStats_OutdatedCountsDeprecatedAndEOL(t *testing.T) {
	f, _ := newPMFixture(t)
	repo := NewComponentRepository(&DB{DB: f.db})
	tenant := seedTestTenant(f.ctx, t, f.db)
	noise := seedTestTenant(f.ctx, t, f.db)
	asset := f.asset(tenant, "private", false, "active", f.at(-pmDay), nil)
	noiseAsset := f.asset(noise, "private", false, "active", f.at(-pmDay), nil)

	comp := func(tn, a shared.ID, status string) {
		cid := shared.NewID()
		f.exec(`INSERT INTO components (id, purl, name, version, ecosystem) VALUES ($1, $2, $3, '1.0.0', 'npm')`,
			cid.String(), "pkg:npm/dead-literal-"+cid.String()+"@1.0.0", "dead-literal-"+cid.String())
		f.exec(`INSERT INTO asset_components (tenant_id, asset_id, component_id, name, version, ecosystem, dependency_type, status)
			VALUES ($1, $2, $3, $5, '1.0.0', 'npm', 'direct', $4)`,
			tn.String(), a.String(), cid.String(), status, "dead-literal-"+cid.String())
	}
	comp(tenant, asset, "active")
	comp(tenant, asset, "deprecated")
	comp(tenant, asset, "end_of_life")
	comp(noise, noiseAsset, "deprecated")

	stats, err := repo.GetStats(f.ctx, tenant)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if stats.TotalComponents != 3 || stats.OutdatedComponents != 2 {
		t.Fatalf("GetStats total=%d outdated=%d, want 3/2", stats.TotalComponents, stats.OutdatedComponents)
	}

	eco, err := repo.GetEcosystemStats(f.ctx, tenant)
	if err != nil {
		t.Fatalf("GetEcosystemStats: %v", err)
	}
	if len(eco) != 1 || eco[0].Outdated != 2 {
		t.Fatalf("GetEcosystemStats = %+v, want one npm row with 2 outdated", eco)
	}
}
