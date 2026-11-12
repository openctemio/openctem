package postgres

// Targets left out when a scan was saved (scans.skipped_targets): stored on
// create, read back, never readable by another tenant.

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestScanSkippedTargets_DB(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanRepository(&DB{DB: db})
	tenantID := seedScanTriggerTenant(ctx, t, db)
	other := seedScanTriggerTenant(ctx, t, db)

	sc, err := scan.NewScan(tenantID, "Partial", shared.ID{}, scan.ScanTypeSingle)
	if err != nil {
		t.Fatal(err)
	}
	sc.SetTargets([]string{"app.example.com"})
	if err := sc.SetSingleScanner("nuclei", nil, 1); err != nil {
		t.Fatal(err)
	}
	sc.SkippedTargets = []scan.SkippedTarget{{Target: "intra.example.com", Code: "zone_none"}, {Target: "www.other.example", Code: "proof_required"}}
	if err := repo.Create(ctx, sc); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM scans WHERE id = $1`, sc.ID.String()) })

	got, err := repo.GetByTenantAndID(ctx, tenantID, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.SkippedTargets) != 2 || got.SkippedTargets[0].Code != "zone_none" || got.SkippedTargets[1].Target != "www.other.example" {
		t.Fatalf("skipped targets = %+v", got.SkippedTargets)
	}
	// A scan saved without skipped targets reads back none.
	plain, _ := scan.NewScan(tenantID, "Full", shared.ID{}, scan.ScanTypeSingle)
	plain.SetTargets([]string{"app.example.com"})
	_ = plain.SetSingleScanner("nuclei", nil, 1)
	if err := repo.Create(ctx, plain); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM scans WHERE id = $1`, plain.ID.String())
	})
	if g, err := repo.GetByTenantAndID(ctx, tenantID, plain.ID); err != nil || len(g.SkippedTargets) != 0 {
		t.Fatalf("plain scan: %+v %v", g, err)
	}
	// Another tenant cannot read it.
	if _, err := repo.GetByTenantAndID(ctx, other, sc.ID); !errors.Is(err, shared.ErrNotFound) && err == nil {
		t.Fatal("another tenant read the scan")
	}
}
