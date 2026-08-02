package integration

import (
	"context"
	"testing"

	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// TestRecomputeFingerprintsForAsset exercises the CORRECT, composite-aware
// post-merge fingerprint recompute (the previous attempt used the wrong 32-char
// algorithm and corrupted ingested findings — this test uses the REAL composite
// scheme so it would have caught that).
//
// An ingested finding stores fingerprint = CompositeFingerprint(asset_id, base)
// and persists `base` in partial_fingerprints. After a merge repoints it to the
// surviving asset (raw UPDATE, no recompute), RecomputeFingerprintsForAsset must
// rebuild the composite for the new asset_id, collapse collisions, and leave
// findings it cannot safely recompute untouched.
func TestRecomputeFingerprintsForAsset(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()

	tenant := createTestTenant(t, db, "fp-recompute")
	assetA := createTestAsset(t, db, tenant, "merge-away")
	keep := createTestAsset(t, db, tenant, "keep")
	repo := postgres.NewFindingRepository(&postgres.DB{DB: db})

	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM findings WHERE tenant_id=$1`, tenant.String())
		_, _ = db.Exec(`DELETE FROM assets WHERE tenant_id=$1`, tenant.String())
		_, _ = db.Exec(`DELETE FROM tenants WHERE id=$1`, tenant.String())
	})

	// insertComposite inserts a finding as ingest would: composite fingerprint +
	// the persisted base. Returns the finding id.
	insertComposite := func(assetID shared.ID, base, msg string) shared.ID {
		t.Helper()
		id := shared.NewID()
		fp := vulnerability.CompositeFingerprint(assetID.String(), base)
		_, err := db.Exec(`
			INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message,
				severity, status, fingerprint, partial_fingerprints, created_at, updated_at)
			VALUES ($1,$2,$3,'sca','trivy',$4,'high','new',$5,$6, NOW(), NOW())`,
			id.String(), tenant.String(), assetID.String(), msg, fp,
			`{"`+vulnerability.FingerprintBaseKey+`":"`+base+`"}`)
		if err != nil {
			t.Fatalf("insert composite finding: %v", err)
		}
		return id
	}
	// Simulate the raw asset-merge repoint (what ApproveAndMerge does).
	moveToKeep := func(id shared.ID) {
		t.Helper()
		if _, err := db.Exec(`UPDATE findings SET asset_id=$1 WHERE id=$2 AND tenant_id=$3`,
			keep.String(), id.String(), tenant.String()); err != nil {
			t.Fatalf("move finding: %v", err)
		}
	}
	fpOf := func(id shared.ID) string {
		t.Helper()
		var fp string
		if err := db.QueryRow(`SELECT fingerprint FROM findings WHERE id=$1`, id.String()).Scan(&fp); err != nil {
			t.Fatalf("read fp: %v", err)
		}
		return fp
	}

	// --- Scenario 1: a moved composite finding is recomputed for the keep asset. ---
	f1 := insertComposite(assetA, "base-unique", "log4j RCE")
	moveToKeep(f1) // now on keep but fingerprint still embeds assetA
	if got, want := fpOf(f1), vulnerability.CompositeFingerprint(keep.String(), "base-unique"); got == want {
		t.Fatal("precondition: moved finding should still carry the stale (assetA) fingerprint")
	}

	updated, deduped, err := repo.RecomputeFingerprintsForAsset(ctx, tenant, keep)
	if err != nil {
		t.Fatalf("recompute: %v", err)
	}
	if updated != 1 || deduped != 0 {
		t.Fatalf("scenario1: expected updated=1 deduped=0, got updated=%d deduped=%d", updated, deduped)
	}
	if got, want := fpOf(f1), vulnerability.CompositeFingerprint(keep.String(), "base-unique"); got != want {
		t.Fatalf("scenario1: fingerprint not recomputed for keep asset\n got=%s\nwant=%s", got, want)
	}
	// Idempotent: a second run changes nothing.
	if up2, dd2, err := repo.RecomputeFingerprintsForAsset(ctx, tenant, keep); err != nil || up2 != 0 || dd2 != 0 {
		t.Fatalf("second recompute should be a no-op, got updated=%d deduped=%d err=%v", up2, dd2, err)
	}

	// --- Scenario 2: a moved finding that collides with a pre-existing keep
	// finding (same base ⇒ same recomputed composite) is deleted as a duplicate.
	_ = insertComposite(keep, "base-shared", "native keep finding") // already correct on keep
	moved := insertComposite(assetA, "base-shared", "moved-in dup")
	moveToKeep(moved)

	up3, dd3, err := repo.RecomputeFingerprintsForAsset(ctx, tenant, keep)
	if err != nil {
		t.Fatalf("recompute (collision): %v", err)
	}
	if dd3 != 1 {
		t.Errorf("expected exactly 1 dedup on composite collision, got deduped=%d (updated=%d)", dd3, up3)
	}
	var remaining int
	if err := db.QueryRow(`SELECT COUNT(*) FROM findings WHERE asset_id=$1 AND fingerprint=$2`,
		keep.String(), vulnerability.CompositeFingerprint(keep.String(), "base-shared")).Scan(&remaining); err != nil {
		t.Fatalf("count survivors: %v", err)
	}
	if remaining != 1 {
		t.Errorf("expected exactly 1 finding for the shared fingerprint, got %d", remaining)
	}

	// --- Scenario 3: a composite finding with NO persisted base (legacy) is left
	// untouched — its base is unrecoverable and guessing would corrupt it. ---
	legacyID := shared.NewID()
	legacyFP := vulnerability.CompositeFingerprint(assetA.String(), "legacy") // 64-char, wrong-for-keep
	if _, err := db.Exec(`
		INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message,
			severity, status, fingerprint, partial_fingerprints, created_at, updated_at)
		VALUES ($1,$2,$3,'sca','trivy','legacy finding','low','new',$4,'{}', NOW(), NOW())`,
		legacyID.String(), tenant.String(), keep.String(), legacyFP); err != nil {
		t.Fatalf("insert legacy finding: %v", err)
	}
	if _, _, err := repo.RecomputeFingerprintsForAsset(ctx, tenant, keep); err != nil {
		t.Fatalf("recompute (legacy): %v", err)
	}
	if got := fpOf(legacyID); got != legacyFP {
		t.Errorf("legacy finding (no stored base) must be left untouched, got %s want %s", got, legacyFP)
	}
}
