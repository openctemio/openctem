package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// The lens filter matches the stored asset_lens, so an alias stored under
// another type's name lands in its own lens: a container registry is stored
// as storage/container_registry but belongs to Containers & Kubernetes, not
// Data. A types filter cannot express that. Other tenants never match.
func TestAssetLensFilter_ListAndStats(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewAssetRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)

	newAsset := func(tn shared.ID, typ, subType string) shared.ID {
		t.Helper()
		id := shared.NewID()
		if _, err := db.ExecContext(ctx,
			`INSERT INTO assets (id, tenant_id, name, asset_type, sub_type) VALUES ($1, $2, $3, $4, NULLIF($5, ''))`,
			id.String(), tn.String(), "lens-"+id.String(), typ, subType); err != nil {
			t.Fatalf("insert asset: %v", err)
		}
		return id
	}
	registry := newAsset(tenant, "storage", "container_registry")
	container := newAsset(tenant, "container", "")
	newAsset(tenant, "storage", "bucket")
	newAsset(tenant, "host", "")
	newAsset(other, "container", "") // another tenant's: never listed

	filter := asset.NewFilter().WithTenantID(tenant.String()).WithLenses(asset.LensContainersK8s)
	res, err := repo.List(ctx, filter, asset.NewListOptions(), pagination.New(1, 50))
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got := map[string]bool{}
	for _, a := range res.Data {
		got[a.ID().String()] = true
	}
	if len(got) != 2 || !got[registry.String()] || !got[container.String()] {
		t.Errorf("containers lens listed %v, want the container and the storage/container_registry alias only", got)
	}

	stats, err := repo.GetAggregateStats(ctx, tenant, asset.AccessScope{}, nil,
		[]string{string(asset.LensData)}, nil, "")
	if err != nil {
		t.Fatalf("GetAggregateStats: %v", err)
	}
	if stats.Total != 1 || stats.ByType["storage"] != 1 {
		t.Errorf("data lens stats total = %d (by type %v), want the bucket only", stats.Total, stats.ByType)
	}
}
