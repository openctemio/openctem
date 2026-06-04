package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
)

// TestAutoResolveStaleByAssets_ExecutesAgainstSchema runs the batched
// auto-resolve against the real schema with a random (empty) tenant so it
// matches nothing and mutates nothing, while still exercising the actual SQL —
// in particular the `asset_id = ANY($2)` binding of a string array against the
// real asset_id column type. A type mismatch (uuid vs text[]) would surface
// here instead of silently in production ingest.
//
// Skipped unless DATABASE_URL is set.
func TestAutoResolveStaleByAssets_ExecutesAgainstSchema(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	repo := NewFindingRepository(&DB{DB: db})

	// Random tenant + assets => no rows match => no mutation, but the query
	// (including ANY($2)) is parsed, planned, and executed for real.
	tenantID := shared.NewID()
	assetIDs := []shared.ID{shared.NewID(), shared.NewID()}

	// nil branch variant (the one the ingest service uses)
	resolved, err := repo.AutoResolveStaleByAssets(ctx, tenantID, assetIDs, "trivy", "scan-test", nil)
	if err != nil {
		t.Fatalf("AutoResolveStaleByAssets (nil branch) failed against schema: %v", err)
	}
	if len(resolved) != 0 {
		t.Fatalf("expected 0 resolved for random tenant, got %d", len(resolved))
	}

	// branch-scoped variant
	branchID := shared.NewID()
	resolved, err = repo.AutoResolveStaleByAssets(ctx, tenantID, assetIDs, "trivy", "scan-test", &branchID)
	if err != nil {
		t.Fatalf("AutoResolveStaleByAssets (branch) failed against schema: %v", err)
	}
	if len(resolved) != 0 {
		t.Fatalf("expected 0 resolved for random tenant, got %d", len(resolved))
	}
}
