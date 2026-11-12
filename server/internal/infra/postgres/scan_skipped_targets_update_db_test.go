package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
)

// Update writes the scan's skipped targets: an edit that replaces the
// targets clears the list recorded at create, and the clear is stored.
func TestScanRepository_UpdateStoresSkippedTargets(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanRepository(&DB{DB: db})
	tenantID, scanID := seedCounterScan(ctx, t, db)

	sc, err := repo.GetByTenantAndID(ctx, tenantID, scanID)
	if err != nil {
		t.Fatal(err)
	}
	sc.SkippedTargets = []scan.SkippedTarget{{Target: "skipped.example.com", Code: "no_entry"}}
	if err := repo.Update(ctx, sc); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err := repo.GetByTenantAndID(ctx, tenantID, scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.SkippedTargets) != 1 || got.SkippedTargets[0].Target != "skipped.example.com" {
		t.Fatalf("skipped targets read back %+v, want the one stored", got.SkippedTargets)
	}

	got.SkippedTargets = nil
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	again, err := repo.GetByTenantAndID(ctx, tenantID, scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.SkippedTargets) != 0 {
		t.Fatalf("skipped targets = %+v after clearing, want none", again.SkippedTargets)
	}
}
