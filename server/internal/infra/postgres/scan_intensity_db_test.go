package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
)

// The scan intensity (RFC-071) is stored and read back, tenant-scoped; the
// database refuses a value outside passive, active and intrusive.
func TestScanRepository_IntensityRoundTrip(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanRepository(&DB{DB: db})
	tenantID, scanID := seedCounterScan(ctx, t, db)

	sc, err := repo.GetByTenantAndID(ctx, tenantID, scanID)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Intensity == "" {
		t.Fatal("a stored scan has no intensity")
	}
	if err := sc.SetIntensity(scan.IntensityPassive); err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(ctx, sc); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err := repo.GetByTenantAndID(ctx, tenantID, scanID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Intensity != scan.IntensityPassive {
		t.Fatalf("intensity read back %q, want passive", got.Intensity)
	}

	// Another tenant's update never reaches the row.
	other, _ := seedCounterScan(ctx, t, db)
	got.TenantID = other
	got.Intensity = scan.IntensityIntrusive
	_ = repo.Update(ctx, got)
	var stored string
	if err := db.QueryRowContext(ctx, `SELECT intensity FROM scans WHERE id = $1`, scanID.String()).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "passive" {
		t.Fatalf("intensity = %q after another tenant's update, want passive", stored)
	}

	if _, err := db.ExecContext(ctx, `UPDATE scans SET intensity = 'loud' WHERE id = $1`, scanID.String()); err == nil {
		t.Fatal("an unknown intensity was stored")
	}
}
