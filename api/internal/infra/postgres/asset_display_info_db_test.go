package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
)

// GetDisplayInfoByIDs replaces a per-asset GetByID loop on the findings list.
// It must stay tenant-scoped: ids of another tenant's assets are silently
// dropped, exactly like GetByID returning not-found for them.
func TestAssetRepository_GetDisplayInfoByIDs_TenantScoped(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewAssetRepository(&DB{DB: db})

	tenantA := seedTestTenant(ctx, t, db)
	tenantB := seedTestTenant(ctx, t, db)
	a1 := seedOwnedAsset(ctx, t, db, tenantA, nil)
	a2 := seedOwnedAsset(ctx, t, db, tenantA, nil)
	b1 := seedOwnedAsset(ctx, t, db, tenantB, nil)

	got, err := repo.GetDisplayInfoByIDs(ctx, tenantA, []shared.ID{a1, a2, b1, shared.NewID()})
	if err != nil {
		t.Fatalf("GetDisplayInfoByIDs: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 tenant-A assets, got %d: %+v", len(got), got)
	}
	if _, ok := got[b1]; ok {
		t.Fatal("tenant B asset returned for tenant A")
	}
	for _, id := range []shared.ID{a1, a2} {
		d, ok := got[id]
		if !ok {
			t.Fatalf("missing tenant-A asset %s", id)
		}
		if d.ID != id || d.Name != "asset-"+id.String() || d.Type != asset.AssetTypeHost {
			t.Errorf("wrong display info for %s: %+v", id, d)
		}
	}

	empty, err := repo.GetDisplayInfoByIDs(ctx, tenantA, nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty input: got %v, %v", empty, err)
	}
}
