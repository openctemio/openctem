package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
)

// A concurrent ingest can create an asset with the same (tenant_id, name) first.
// When the second ingest's UpsertBatch runs, ON CONFLICT keeps the winner's row
// id and discards the loser's locally-generated id. Before the fix UpsertBatch
// only returned created/updated counts, so the caller kept linking findings to
// the loser's non-persisted id — an FK drop / orphaned finding. UpsertBatch now
// returns persistedIDs (name -> the id the row actually holds) so the caller can
// remap. This test proves the loser gets the winner's id back.
func TestUpsertBatch_ConcurrentCreateSameName_ReturnsWinnerID(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	repo := NewAssetRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)

	// The loser: an asset object built locally by this ingest with its own id.
	loser, err := asset.NewAssetWithTenant(tenantID, "race-host__test.example.com", asset.AssetTypeHost, asset.CriticalityMedium)
	if err != nil {
		t.Fatalf("new asset: %v", err)
	}
	loserID := loser.ID()
	name := loser.Name()

	// The winner: a concurrent ingest already persisted this exact name under a
	// different id. Insert it directly to simulate having lost the race.
	winnerID := shared.NewID()
	if winnerID.Equals(loserID) {
		t.Fatal("winner and loser ids collided; test is meaningless")
	}
	_, _ = db.ExecContext(ctx, "DELETE FROM assets WHERE tenant_id=$1 AND name=$2", tenantID.String(), name)
	if _, err := db.ExecContext(ctx,
		`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1,$2,$3,'host')`,
		winnerID.String(), tenantID.String(), name); err != nil {
		t.Fatalf("seed winner asset: %v", err)
	}

	created, updated, persistedIDs, err := repo.UpsertBatch(ctx, []*asset.Asset{loser})
	if err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}
	if created != 0 || updated != 1 {
		t.Errorf("expected the loser to update the winner's row (created=0 updated=1), got created=%d updated=%d", created, updated)
	}

	pid, ok := persistedIDs[name]
	if !ok {
		t.Fatalf("persistedIDs is missing the asset name %q; caller cannot remap", name)
	}
	if !pid.Equals(winnerID) {
		t.Errorf("persisted id = %s, want the winner's id %s", pid.String(), winnerID.String())
	}
	if pid.Equals(loserID) {
		t.Error("persisted id is the loser's non-persisted id; findings linked to it would be orphaned")
	}

	// The row in the DB must still be the winner's id, never the loser's.
	var dbID string
	if err := db.QueryRowContext(ctx, `SELECT id FROM assets WHERE tenant_id=$1 AND name=$2`, tenantID.String(), name).Scan(&dbID); err != nil {
		t.Fatalf("read persisted asset: %v", err)
	}
	if dbID != winnerID.String() {
		t.Errorf("DB row id = %s, want winner %s", dbID, winnerID.String())
	}
}
