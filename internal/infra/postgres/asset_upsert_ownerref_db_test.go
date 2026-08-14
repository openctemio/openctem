package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/asset"
)

// TestUpsertBatch_PersistsOwnerRef verifies that the batch/discovery upsert path
// (UpsertBatch) persists owner_ref. This column was previously omitted from the
// batch INSERT column list AND the ON CONFLICT clause, so a discovery-ingested
// asset whose owner reference was extracted from the scan report
// (compliance.regulatory_owner / repository owner / properties.owner) had that
// owner silently dropped on create — even though the single-row Create/Update
// path persisted it. The asset is read back with GetByID WITHOUT any intervening
// Update, so a regression (owner_ref dropped from the batch INSERT again) fails
// here. Skipped unless DATABASE_URL is set.
func TestUpsertBatch_PersistsOwnerRef(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	repo := NewAssetRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)

	const (
		wantName  = "owner-ref-batch__test.example.com"
		wantOwner = "platform-security-team__test"
	)

	a, err := asset.NewAssetWithTenant(tenantID, wantName, asset.AssetTypeHost, asset.CriticalityMedium)
	if err != nil {
		t.Fatalf("new asset: %v", err)
	}
	a.SetOwnerRef(wantOwner)

	// Clean up any prior run, then clean up this run on exit.
	_, _ = db.ExecContext(ctx, "DELETE FROM assets WHERE tenant_id = $1 AND name = $2", tenantID.String(), wantName)
	defer func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM assets WHERE tenant_id = $1 AND name = $2", tenantID.String(), wantName)
	}()

	created, _, _, err := repo.UpsertBatch(ctx, []*asset.Asset{a})
	if err != nil {
		t.Fatalf("upsert batch: %v", err)
	}
	if created != 1 {
		t.Fatalf("expected 1 created, got %d", created)
	}

	got, err := repo.GetByID(ctx, tenantID, a.ID())
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if got.OwnerRef() != wantOwner {
		t.Errorf("owner_ref dropped by UpsertBatch: got %q, want %q", got.OwnerRef(), wantOwner)
	}
}
