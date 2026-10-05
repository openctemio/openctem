package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// GetFindingTrend buckets one range scan by month; pin the bucketing: current
// and 2-months-ago findings land in their month, older-than-window, draft and
// other-tenant findings are excluded, and every month in the window is
// present (zero-filled).
func TestGetFindingTrend_MonthBuckets(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewDashboardRepository(db)

	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)
	otherAsset := seedOwnedAsset(ctx, t, db, other, nil)

	seed := func(tid, aid shared.ID, severity, status, age string) {
		t.Helper()
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `
			INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, created_at)
			VALUES ($1, $2, $3, 'sca', 'test', 'msg', $4, $5, $6, NOW() - $7::interval)`,
			id.String(), tid.String(), aid.String(), severity, id.String(), status, age); err != nil {
			t.Fatalf("seed finding: %v", err)
		}
	}
	seed(tenant, asset, "critical", "new", "0 days")
	seed(tenant, asset, "high", "resolved", "0 days")
	seed(tenant, asset, "low", "draft", "0 days")        // excluded: draft
	seed(tenant, asset, "medium", "new", "2 months")     // 2 months ago
	seed(tenant, asset, "critical", "new", "8 months")   // outside 6-month window
	seed(other, otherAsset, "critical", "new", "0 days") // other tenant

	trend, err := repo.GetFindingTrend(ctx, tenant, nil, 6)
	if err != nil {
		t.Fatalf("GetFindingTrend: %v", err)
	}
	if len(trend) != 6 {
		t.Fatalf("want 6 monthly points, got %d", len(trend))
	}
	cur := trend[5]
	if cur.Critical != 1 || cur.High != 1 || cur.Low != 0 {
		t.Errorf("current month wrong: %+v", cur)
	}
	if trend[3].Medium != 1 {
		t.Errorf("2-months-ago bucket wrong: %+v", trend[3])
	}
	total := 0
	for _, p := range trend {
		total += p.Critical + p.High + p.Medium + p.Low + p.Info
	}
	if total != 3 {
		t.Errorf("want 3 findings in window (draft/old/other-tenant excluded), got %d: %+v", total, trend)
	}
}
