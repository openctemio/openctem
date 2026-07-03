package integration

import (
	"context"
	"testing"

	"github.com/openctemio/api/internal/infra/postgres"
)

// TestRecomputeFingerprintsForAsset verifies post-merge fingerprint hygiene.
//
// After an asset merge repoints findings to the surviving asset, their stored
// fingerprint is stale (it embeds the old asset_id). RecomputeFingerprintsForAsset
// must (1) recompute and persist the correct fingerprint, (2) be idempotent, and
// (3) collapse a moved-in finding that now collides with an existing finding on
// the surviving asset (UNIQUE(tenant_id, fingerprint)).
func TestRecomputeFingerprintsForAsset(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()

	tenant := createTestTenant(t, db, "fp-recompute")
	keep := createTestAsset(t, db, tenant, "keep-fp")
	repo := postgres.NewFindingRepository(&postgres.DB{DB: db})

	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM findings WHERE tenant_id=$1`, tenant.String())
		_, _ = db.Exec(`DELETE FROM assets WHERE tenant_id=$1`, tenant.String())
		_, _ = db.Exec(`DELETE FROM tenants WHERE id=$1`, tenant.String())
	})

	// --- Scenario 1: a stale fingerprint is corrected, re-running is a no-op. ---
	f1 := createTestFinding(t, db, tenant, keep, "unique-finding-msg")

	var staleFP string
	if err := db.QueryRow(`SELECT fingerprint FROM findings WHERE id=$1`, f1.String()).Scan(&staleFP); err != nil {
		t.Fatalf("read stale fp: %v", err)
	}

	updated, deduped, err := repo.RecomputeFingerprintsForAsset(ctx, tenant, keep)
	if err != nil {
		t.Fatalf("recompute: %v", err)
	}
	if updated != 1 || deduped != 0 {
		t.Fatalf("scenario1: expected updated=1 deduped=0, got updated=%d deduped=%d", updated, deduped)
	}

	var newFP string
	if err := db.QueryRow(`SELECT fingerprint FROM findings WHERE id=$1`, f1.String()).Scan(&newFP); err != nil {
		t.Fatalf("read recomputed fp: %v", err)
	}
	if newFP == staleFP {
		t.Errorf("fingerprint should have changed from stale %q", staleFP)
	}
	if len(newFP) != 32 {
		t.Errorf("recomputed fingerprint should be 32 hex chars, got %q (len %d)", newFP, len(newFP))
	}

	// Idempotent: a second run over the now-consistent finding changes nothing.
	up2, dd2, err := repo.RecomputeFingerprintsForAsset(ctx, tenant, keep)
	if err != nil {
		t.Fatalf("recompute (idempotent run): %v", err)
	}
	if up2 != 0 || dd2 != 0 {
		t.Errorf("second recompute should be a no-op, got updated=%d deduped=%d", up2, dd2)
	}

	// --- Scenario 2: a moved-in duplicate collides and is deleted. ---
	// Same asset + same message (empty rule/path/line) → same recomputed fingerprint
	// as f1, so it collides on UNIQUE(tenant_id, fingerprint).
	_ = createTestFinding(t, db, tenant, keep, "unique-finding-msg")

	up3, dd3, err := repo.RecomputeFingerprintsForAsset(ctx, tenant, keep)
	if err != nil {
		t.Fatalf("recompute (collision run): %v", err)
	}
	if dd3 != 1 {
		t.Errorf("expected exactly 1 dedup on fingerprint collision, got deduped=%d (updated=%d)", dd3, up3)
	}

	var remaining int
	if err := db.QueryRow(`SELECT COUNT(*) FROM findings WHERE asset_id=$1 AND message='unique-finding-msg'`,
		keep.String()).Scan(&remaining); err != nil {
		t.Fatalf("count survivors: %v", err)
	}
	if remaining != 1 {
		t.Errorf("expected 1 finding to survive dedup, got %d", remaining)
	}
}
