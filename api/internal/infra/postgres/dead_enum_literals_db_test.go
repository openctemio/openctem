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
