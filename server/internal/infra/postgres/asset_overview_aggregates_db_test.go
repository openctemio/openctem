package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
)

// The overview's per-type breakdown and average risk score count the same
// attribution population as its stat tiles: a rejected or needs-review name
// is in neither, so the breakdown sums to the total and the average ignores
// assets that are not the organization's.
func TestOverviewAggregates_FollowAttribution(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewAssetRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)

	mine := seedOwnedAsset(ctx, t, db, tenant, nil)
	rejected := seedOwnedAsset(ctx, t, db, tenant, nil)
	review := seedOwnedAsset(ctx, t, db, tenant, nil)
	for id, score := range map[string]int{mine.String(): 20, rejected.String(): 100, review.String(): 100} {
		if _, err := db.ExecContext(ctx, `UPDATE assets SET risk_score = $2 WHERE id = $1`, id, score); err != nil {
			t.Fatal(err)
		}
	}
	for id, st := range map[string]string{rejected.String(): "rejected", review.String(): "needs_review"} {
		if _, err := db.ExecContext(ctx, `INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence) VALUES ($1, $2, $3, 50)`,
			id, tenant.String(), st); err != nil {
			t.Fatal(err)
		}
	}

	af, _, _ := attribution.ParseFilter([]string{attribution.FilterAttributed})
	breakdown, err := repo.GetAssetTypeBreakdown(ctx, tenant, nil, &af)
	if err != nil {
		t.Fatal(err)
	}
	sum := 0
	for _, s := range breakdown {
		sum += s.Total
	}
	if sum != 1 {
		t.Errorf("breakdown sums to %d, want 1 (only the attributed asset)", sum)
	}
	if avg, err := repo.GetAverageRiskScore(ctx, tenant, nil, &af); err != nil || avg != 20 {
		t.Errorf("average = %v, %v, want 20", avg, err)
	}

	// Without a filter every live asset is counted (callers outside the overview).
	all, _ := repo.GetAssetTypeBreakdown(ctx, tenant, nil, nil)
	sum = 0
	for _, s := range all {
		sum += s.Total
	}
	if sum != 3 {
		t.Errorf("unfiltered breakdown sums to %d, want 3", sum)
	}
}
