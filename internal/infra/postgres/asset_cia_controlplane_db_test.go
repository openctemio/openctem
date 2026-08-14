package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/asset"
)

// TestAsset_CIAImpactRoundTrip verifies the CTEM Scoping CIA impact ratings
// survive a Create -> GetByID round trip and an Update. Regression guard for the
// silently-dropped-column class (the ratings must be threaded through the INSERT,
// UPDATE, SELECT and scan paths). Skipped unless DATABASE_URL is set.
func TestAsset_CIAImpactRoundTrip(t *testing.T) {
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

	const wantName = "cia-roundtrip__test.example.com"

	a, err := asset.NewAssetWithTenant(tenantID, wantName, asset.AssetTypeDatabase, asset.CriticalityHigh)
	if err != nil {
		t.Fatalf("new asset: %v", err)
	}
	if err := a.SetImpactConfidentiality(asset.ImpactRatingHigh); err != nil {
		t.Fatalf("set C: %v", err)
	}
	if err := a.SetImpactIntegrity(asset.ImpactRatingModerate); err != nil {
		t.Fatalf("set I: %v", err)
	}
	if err := a.SetImpactAvailability(asset.ImpactRatingLow); err != nil {
		t.Fatalf("set A: %v", err)
	}

	_, _ = db.ExecContext(ctx, "DELETE FROM assets WHERE tenant_id = $1 AND name = $2", tenantID.String(), wantName)
	defer func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM assets WHERE tenant_id = $1 AND name = $2", tenantID.String(), wantName)
	}()

	if err := repo.Create(ctx, a); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := repo.GetByID(ctx, tenantID, a.ID())
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if got.ImpactConfidentiality() != asset.ImpactRatingHigh ||
		got.ImpactIntegrity() != asset.ImpactRatingModerate ||
		got.ImpactAvailability() != asset.ImpactRatingLow {
		t.Fatalf("CIA dropped on Create/read: C=%q I=%q A=%q",
			got.ImpactConfidentiality(), got.ImpactIntegrity(), got.ImpactAvailability())
	}

	// Update path: change one leg, clear another.
	if err := got.SetImpactAvailability(asset.ImpactRatingHigh); err != nil {
		t.Fatalf("update A: %v", err)
	}
	if err := got.SetImpactConfidentiality(""); err != nil {
		t.Fatalf("clear C: %v", err)
	}
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}

	got2, err := repo.GetByID(ctx, tenantID, a.ID())
	if err != nil {
		t.Fatalf("get by id (2): %v", err)
	}
	if got2.ImpactAvailability() != asset.ImpactRatingHigh {
		t.Errorf("ImpactAvailability after update = %q, want high", got2.ImpactAvailability())
	}
	if got2.ImpactConfidentiality() != "" {
		t.Errorf("ImpactConfidentiality after clear = %q, want empty", got2.ImpactConfidentiality())
	}
	if got2.ImpactIntegrity() != asset.ImpactRatingModerate {
		t.Errorf("ImpactIntegrity after update = %q, want moderate", got2.ImpactIntegrity())
	}
}

// TestRelationship_ControlPlaneRoundTrip verifies the control-plane dependency
// flag survives a Create -> GetByID round trip on an asset relationship.
// Skipped unless DATABASE_URL is set.
func TestRelationship_ControlPlaneRoundTrip(t *testing.T) {
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

	assetRepo := NewAssetRepository(&DB{DB: db})
	relRepo := NewAssetRelationshipRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)

	const srcName = "cp-src__test.example.com"
	const dstName = "cp-idp__test.example.com"

	src, err := asset.NewAssetWithTenant(tenantID, srcName, asset.AssetTypeService, asset.CriticalityHigh)
	if err != nil {
		t.Fatalf("new src: %v", err)
	}
	dst, err := asset.NewAssetWithTenant(tenantID, dstName, asset.AssetTypeIdentity, asset.CriticalityHigh)
	if err != nil {
		t.Fatalf("new dst: %v", err)
	}

	cleanup := func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM asset_relationships WHERE tenant_id = $1", tenantID.String())
		_, _ = db.ExecContext(ctx, "DELETE FROM assets WHERE tenant_id = $1 AND name IN ($2, $3)", tenantID.String(), srcName, dstName)
	}
	cleanup()
	defer cleanup()

	if err := assetRepo.Create(ctx, src); err != nil {
		t.Fatalf("create src: %v", err)
	}
	if err := assetRepo.Create(ctx, dst); err != nil {
		t.Fatalf("create dst: %v", err)
	}

	rel, err := asset.NewRelationship(tenantID, src.ID(), dst.ID(), asset.RelTypeDependsOn)
	if err != nil {
		t.Fatalf("new relationship: %v", err)
	}
	rel.SetControlPlane(true)
	if err := relRepo.Create(ctx, rel); err != nil {
		t.Fatalf("create relationship: %v", err)
	}

	got, err := relRepo.GetByID(ctx, tenantID, rel.ID())
	if err != nil {
		t.Fatalf("get relationship: %v", err)
	}
	if !got.IsControlPlane() {
		t.Error("is_control_plane dropped on Create/read")
	}
}
