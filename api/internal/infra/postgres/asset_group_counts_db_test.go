package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RFC-042 §6.3.8: the per-kind group counters key on the stored class and
// sub-type. They used to compare asset_type with alias names (website,
// credential) that are never stored, so website_count was always 0. Members
// of another tenant never count.
func TestAssetGroupRecalculateCounts_ByStoredClass_DB(t *testing.T) {
	db, ctx := openRegistryDB(t)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q[:40], err)
		}
	}
	newTenant := func() shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'group counts', $2)`, id.String(), "gc-"+id.String())
		t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id.String()) })
		return id
	}
	tenant, other := newTenant(), newTenant()
	group := shared.NewID()
	exec(`INSERT INTO asset_groups (id, tenant_id, name) VALUES ($1, $2, 'counts')`, group.String(), tenant.String())
	add := func(tenantID shared.ID, name string, typ asset.AssetType, sub string) {
		t.Helper()
		id := shared.NewID()
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, sub_type) VALUES ($1, $2, $3, $4, NULLIF($5, ''))`,
			id.String(), tenantID.String(), name, string(typ), sub)
		exec(`INSERT INTO asset_group_members (asset_group_id, asset_id) VALUES ($1, $2)`, group.String(), id.String())
	}
	add(tenant, "example.com", asset.AssetTypeDomain, "")
	add(tenant, "www.example.com", asset.AssetTypeSubdomain, "")
	add(tenant, "https://app.example.com", asset.AssetTypeApplication, "website")
	add(tenant, "https://legacy.example.com", asset.AssetTypeApplication, "")
	add(tenant, "https://api.example.com", asset.AssetTypeApplication, "api")
	add(tenant, "com.example.app", asset.AssetTypeApplication, "mobile_app")
	add(tenant, "10.0.0.1:22", asset.AssetTypeService, "open_port")
	add(tenant, "github.com/acme/app", asset.AssetTypeRepository, "")
	add(tenant, "aws-123", asset.AssetTypeCloudAccount, "")
	add(tenant, "bucket-a", asset.AssetTypeStorage, "bucket")
	add(tenant, "web-1", asset.AssetTypeHost, "")
	add(other, "https://foreign.example.org", asset.AssetTypeApplication, "website")

	repo := NewAssetGroupRepository(&DB{DB: db})
	if err := repo.RecalculateCounts(ctx, group); err != nil {
		t.Fatal(err)
	}
	var total, domains, websites, services, repos, cloud, creds int
	if err := db.QueryRowContext(ctx, `SELECT asset_count, domain_count, website_count, service_count,
		repository_count, cloud_count, credential_count FROM asset_groups WHERE id = $1`, group.String()).
		Scan(&total, &domains, &websites, &services, &repos, &cloud, &creds); err != nil {
		t.Fatal(err)
	}
	got := []int{total, domains, websites, services, repos, cloud, creds}
	want := []int{11, 2, 2, 2, 1, 2, 0}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("counts (total, domain, website, service, repository, cloud, credential) = %v, want %v", got, want)
		}
	}
}
