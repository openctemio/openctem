package postgres

import (
	"context"
	"testing"
)

// Every by-severity count reports an info bucket, with none (CVSS 0.0) folded
// into it, and the bucket is present at zero when there is nothing to count.
// Another tenant's informational findings are never counted.
func TestDashboardStats_InfoBucket(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewDashboardRepository(db)

	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	empty := seedTestTenant(ctx, t, db)
	host := seedDashAsset(ctx, t, db, tenant, "host", "-", "active", 0)
	otherHost := seedDashAsset(ctx, t, db, other, "host", "-", "active", 0)

	seedDashFinding(ctx, t, db, tenant, host, "high", "new", nil)
	seedDashFinding(ctx, t, db, tenant, host, "info", "new", nil)
	seedDashFinding(ctx, t, db, tenant, host, "none", "new", nil)
	seedDashFinding(ctx, t, db, other, otherHost, "info", "new", nil)

	all, err := repo.GetAllStats(ctx, tenant, nil)
	if err != nil {
		t.Fatalf("GetAllStats: %v", err)
	}
	fs, err := repo.GetFindingStats(ctx, tenant)
	if err != nil {
		t.Fatalf("GetFindingStats: %v", err)
	}
	for name, by := range map[string]map[string]int{"GetAllStats": all.Findings.BySeverity, "GetFindingStats": fs.BySeverity} {
		if by["info"] != 2 || by["high"] != 1 {
			t.Errorf("%s: want info=2 (info+none, tenant-scoped) high=1, got %+v", name, by)
		}
		if _, ok := by["none"]; ok {
			t.Errorf("%s: none must be folded into info, got %+v", name, by)
		}
	}

	zero, err := repo.GetAllStats(ctx, empty, nil)
	if err != nil {
		t.Fatalf("GetAllStats(empty): %v", err)
	}
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if n, ok := zero.Findings.BySeverity[sev]; !ok || n != 0 {
			t.Errorf("empty tenant: bucket %q = (%d, present=%v), want present at 0", sev, n, ok)
		}
	}
}
