package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// An asset can be saved as Not rated (criticality none): the domain and API
// accept it, and the CHECK must too. The informational finding counted on it
// includes none-severity findings.
func TestAssetCriticalityNone_RoundTrip(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewAssetRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)

	a, err := asset.NewAssetWithTenant(tenantID, "not-rated__test.example.com", asset.AssetTypeDomain, asset.CriticalityNone)
	if err != nil {
		t.Fatalf("new asset: %v", err)
	}
	if err := repo.Create(ctx, a); err != nil {
		t.Fatalf("create asset with criticality none: %v", err)
	}
	seedDashFinding(ctx, t, db, tenantID, a.ID(), "info", "new", nil)
	seedDashFinding(ctx, t, db, tenantID, a.ID(), "none", "new", nil)
	seedDashFinding(ctx, t, db, tenantID, a.ID(), "medium", "new", nil)

	got, err := repo.GetByID(ctx, tenantID, a.ID())
	if err != nil {
		t.Fatalf("get asset: %v", err)
	}
	if got.Criticality() != asset.CriticalityNone {
		t.Errorf("criticality = %q, want none", got.Criticality())
	}
	c := got.FindingSeverityCounts()
	if c == nil || c.Info != 2 || c.Medium != 1 {
		t.Errorf("severity counts = %+v, want info=2 (info+none) medium=1", c)
	}

	// Moving between none and a rated level both ways persists.
	if err := got.UpdateCriticality(asset.CriticalityHigh); err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("update to high: %v", err)
	}
	if err := got.UpdateCriticality(asset.CriticalityNone); err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("update back to none: %v", err)
	}
}
