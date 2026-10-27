package postgres

// Continuous coverage runs (system-triggered, on a scan the platform manages)
// are listed, counted and labelled like any other run of the tenant, and the
// origin filter can leave them out or show only them. A tenant never sees or
// names another tenant's managed scans.

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

func TestRunList_CoverageRunsListedCountedAndFilterable_DB(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanRunRepository(&DB{DB: db})

	tenantA, userScan := seedCounterScan(ctx, t, db)
	coverageScan := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, ad_hoc, managed_by, managed_key)
		 VALUES ($1, $2, 'Continuous coverage: resolve.dns', 'single', 'dnsx', true, 'coverage', 'resolve.dns')`,
		coverageScan.String(), tenantA.String()); err != nil {
		t.Fatalf("seed managed scan: %v", err)
	}
	tenantB, scanB := seedCounterScan(ctx, t, db)
	if _, err := db.ExecContext(ctx, `UPDATE scans SET managed_by = 'coverage', managed_key = 'resolve.dns', ad_hoc = true WHERE id = $1`, scanB.String()); err != nil {
		t.Fatal(err)
	}

	userRun := seedCounterRun(ctx, t, repo, tenantA, userScan)
	covRun := seedCounterRun(ctx, t, repo, tenantA, coverageScan)
	if _, err := db.ExecContext(ctx, `UPDATE scan_runs SET trigger_type = $1, triggered_by = 'policy:coverage' WHERE id = $2`,
		string(scanworkflow.TriggerTypeSystem), covRun.ID.String()); err != nil {
		t.Fatal(err)
	}
	foreign := seedCounterRun(ctx, t, repo, tenantB, scanB)

	list := func(origin scanrun.RunOrigin) map[shared.ID]bool {
		t.Helper()
		res, err := repo.List(ctx, scanrun.RunFilter{TenantID: &tenantA, Origin: origin}, pagination.New(1, 50))
		if err != nil {
			t.Fatal(err)
		}
		out := map[shared.ID]bool{}
		for _, r := range res.Data {
			out[r.ID] = true
		}
		return out
	}

	if got := list(""); len(got) != 2 || !got[userRun.ID] || !got[covRun.ID] {
		t.Fatalf("all origins = %v, want the user run and the coverage run", got)
	}
	if got := list(scanrun.RunOriginSystem); len(got) != 1 || !got[covRun.ID] {
		t.Fatalf("system origin = %v, want only the coverage run", got)
	}
	if got := list(scanrun.RunOriginUser); len(got) != 1 || !got[userRun.ID] {
		t.Fatalf("user origin = %v, want only the user run", got)
	}
	for _, o := range []scanrun.RunOrigin{"", scanrun.RunOriginSystem, scanrun.RunOriginUser} {
		if list(o)[foreign.ID] {
			t.Fatalf("origin %q listed another tenant's run", o)
		}
	}

	// The counters behind the Runs strip count the coverage run too.
	stats, err := repo.GetStatsByTenant(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 2 {
		t.Fatalf("stats total = %d, want 2", stats.Total)
	}

	// The managing policy is named for the tenant's own managed scan only.
	got, err := repo.ScanManagers(ctx, tenantA, []shared.ID{userScan, coverageScan, scanB})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[coverageScan] != "coverage" {
		t.Fatalf("scan managers = %v, want only the tenant's coverage scan", got)
	}
}
