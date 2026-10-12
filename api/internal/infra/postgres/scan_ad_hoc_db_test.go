package postgres

// Unsaved quick scans (scans.ad_hoc, migration 000271): stored and read back,
// left out of the Configurations list and the counts, listed on request, and
// kept once saved.

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

func TestScanAdHoc_ListStatsAndSave_DB(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanRepository(&DB{DB: db})
	tenantID := seedScanTriggerTenant(ctx, t, db)

	newScan := func(name string, adHoc bool) *scan.Scan {
		t.Helper()
		sc, err := scan.NewScan(tenantID, name, shared.ID{}, scan.ScanTypeSingle)
		if err != nil {
			t.Fatal(err)
		}
		sc.SetTargets([]string{"example.com"})
		if err := sc.SetSingleScanner("nuclei", nil, 1); err != nil {
			t.Fatal(err)
		}
		sc.AdHoc = adHoc
		if err := repo.Create(ctx, sc); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.Background(), `DELETE FROM scans WHERE id = $1`, sc.ID.String())
		})
		return sc
	}
	saved := newScan("Weekly SCA", false)
	quick := newScan("Quick Scan - 20261002-101010", true)

	got, err := repo.GetByTenantAndID(ctx, tenantID, quick.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.AdHoc {
		t.Fatal("ad_hoc not stored or not read back")
	}

	list := func(exclude bool) []string {
		t.Helper()
		res, err := repo.List(ctx, scan.Filter{TenantID: &tenantID, ExcludeAdHoc: exclude}, pagination.New(1, 50))
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, s := range res.Data {
			names = append(names, s.Name)
		}
		return names
	}
	if names := list(true); len(names) != 1 || names[0] != saved.Name {
		t.Fatalf("configurations list = %v, want only %q", names, saved.Name)
	}
	if names := list(false); len(names) != 2 {
		t.Fatalf("list with ad-hoc scans = %v, want both", names)
	}

	stats, err := repo.GetStats(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 1 {
		t.Fatalf("stats total = %d, want 1 (the unsaved quick scan is not a configuration)", stats.Total)
	}

	// Save as scan: it becomes a configuration under its new name.
	if err := got.SaveAsConfiguration("Nightly recon"); err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	if names := list(true); len(names) != 2 {
		t.Fatalf("after saving, configurations = %v, want both", names)
	}
	again, err := repo.GetByTenantAndID(ctx, tenantID, quick.ID)
	if err != nil {
		t.Fatal(err)
	}
	if again.AdHoc || again.Name != "Nightly recon" {
		t.Fatalf("after saving: ad_hoc=%v name=%q", again.AdHoc, again.Name)
	}
}
