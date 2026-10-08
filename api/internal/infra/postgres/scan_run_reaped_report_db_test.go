package postgres

import (
	"context"
	"testing"
	"time"
)

// research/62 P0-11: a run the reaper ends must fire the run-finished event
// like any other, so the reaper reports which runs it ended, each with its
// own tenant.
func TestMarkTimedOutRunsReporting_ReportsTheRunsItEnded(t *testing.T) {
	ctx := context.Background()
	db := openTimeoutDB(t)
	repo := NewScanRunRepository(&DB{DB: db})
	tenant := seedScanTriggerTenant(ctx, t, db)
	tpl := seedTimeoutTemplate(ctx, t, db, tenant)
	scan := seedTimeoutScan(ctx, t, db, tenant, 60)
	late := seedRun(ctx, t, db, tenant, tpl, &scan, "running", 2*time.Hour)
	fresh := seedRun(ctx, t, db, tenant, tpl, &scan, "running", time.Second)

	reaped, err := repo.MarkTimedOutRunsReporting(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range reaped {
		if r.RunID == fresh {
			t.Fatal("a run inside its deadline was reported")
		}
		if r.RunID == late {
			found = true
			if r.TenantID != tenant {
				t.Fatalf("reaped run reported with tenant %s, want %s", r.TenantID, tenant)
			}
		}
	}
	if !found {
		t.Fatalf("the run past its deadline was not reported (%d reported)", len(reaped))
	}
}
