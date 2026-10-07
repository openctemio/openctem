package postgres

// GET /scan-runs?scan_id= (a scan's "View all runs"): the list narrows to that
// scan's runs inside the caller's tenant. Another tenant's scan id is a filter
// that matches nothing, never a way to read that tenant's runs.

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

func TestRunList_FilterByScan_DB(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanRunRepository(&DB{DB: db})
	tenantA, scanA1 := seedCounterScan(ctx, t, db)
	_, scanA2 := seedCounterScan(ctx, t, db)
	tenantB, scanB := seedCounterScan(ctx, t, db)
	// seedCounterScan creates its own tenant each time; move the second scan
	// into tenant A so tenant A has two scans.
	if _, err := db.ExecContext(ctx, `UPDATE scans SET tenant_id = $1, name = 'counter probe 2' WHERE id = $2`, tenantA.String(), scanA2.String()); err != nil {
		t.Fatal(err)
	}

	r1 := seedCounterRun(ctx, t, repo, tenantA, scanA1)
	r2 := seedCounterRun(ctx, t, repo, tenantA, scanA1)
	seedCounterRun(ctx, t, repo, tenantA, scanA2)
	seedCounterRun(ctx, t, repo, tenantB, scanB)

	list := func(tenant, scan shared.ID) map[shared.ID]bool {
		t.Helper()
		res, err := repo.List(ctx, scanrun.RunFilter{TenantID: &tenant, ScanID: &scan}, pagination.New(1, 50))
		if err != nil {
			t.Fatal(err)
		}
		out := map[shared.ID]bool{}
		for _, r := range res.Data {
			out[r.ID] = true
		}
		return out
	}

	got := list(tenantA, scanA1)
	if len(got) != 2 || !got[r1.ID] || !got[r2.ID] {
		t.Fatalf("scan filter = %v, want exactly r1 and r2", got)
	}
	if got := list(tenantA, scanB); len(got) != 0 {
		t.Fatalf("tenant A filtering on tenant B's scan got %d runs, want 0", len(got))
	}
}
