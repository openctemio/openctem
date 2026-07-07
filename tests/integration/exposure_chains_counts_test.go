package integration

import (
	"context"
	"testing"

	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/domain/shared"
)

// TestKEVCriticalCountsByAsset verifies the aggregate that feeds exposure-chain
// analysis: it counts only OPEN findings, and buckets KEV vs critical correctly.
func TestKEVCriticalCountsByAsset(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()

	tenant := createTestTenant(t, db, "kev-counts")
	assetA := createTestAsset(t, db, tenant, "asset-a")
	assetB := createTestAsset(t, db, tenant, "asset-b")

	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM findings WHERE tenant_id=$1`, tenant.String())
		_, _ = db.Exec(`DELETE FROM assets WHERE tenant_id=$1`, tenant.String())
		_, _ = db.Exec(`DELETE FROM tenants WHERE id=$1`, tenant.String())
	})

	insert := func(assetID shared.ID, severity, status string, isKEV bool, fp string) {
		t.Helper()
		_, err := db.Exec(`
			INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message,
				severity, status, is_in_kev, fingerprint, created_at, updated_at)
			VALUES ($1,$2,$3,'manual','test',$4,$5,$6,$7,$8, NOW(), NOW())`,
			shared.NewID().String(), tenant.String(), assetID.String(),
			"msg-"+fp, severity, status, isKEV, fp)
		if err != nil {
			t.Fatalf("insert finding: %v", err)
		}
	}

	// asset A: 1 open KEV (high), 1 open critical, 1 RESOLVED critical (excluded).
	insert(assetA, "high", "new", true, "a-kev-1")
	insert(assetA, "critical", "confirmed", false, "a-crit-1")
	insert(assetA, "critical", "resolved", false, "a-crit-resolved")
	// A KEV finding whose fix is applied but NOT yet verified is still a live
	// exposure — it must be counted (fix_applied is in the canonical active set).
	insert(assetA, "high", "fix_applied", true, "a-kev-fixapplied")
	// asset B: 1 open low non-KEV (must not appear at all).
	insert(assetB, "low", "new", false, "b-low-1")

	repo := postgres.NewFindingRepository(&postgres.DB{DB: db})
	kev, critical, err := repo.KEVCriticalCountsByAsset(ctx, tenant)
	if err != nil {
		t.Fatalf("KEVCriticalCountsByAsset: %v", err)
	}

	if kev[assetA.String()] != 2 {
		t.Errorf("asset A KEV: expected 2 (new + fix_applied), got %d", kev[assetA.String()])
	}
	if critical[assetA.String()] != 1 {
		t.Errorf("asset A critical (open only): expected 1, got %d", critical[assetA.String()])
	}
	if _, ok := kev[assetB.String()]; ok {
		t.Errorf("asset B should not appear in KEV map (no KEV findings)")
	}
	if _, ok := critical[assetB.String()]; ok {
		t.Errorf("asset B should not appear in critical map (only a low finding)")
	}
}
