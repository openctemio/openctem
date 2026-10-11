package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ResolvedAddresses lists an IP address asset with every name resolving to
// it (each name paired with its own asset id), only the tenant's own rows,
// and never a deleted asset.
func TestScopeAddressRepository_ResolvedAddresses_DB(t *testing.T) {
	ctx := context.Background()
	db := openSensorDB(t)
	repo := NewScopeAddressRepository(&DB{DB: db})
	org, other := shared.NewID(), shared.NewID()
	for _, id := range []shared.ID{org, other} {
		mustExec(t, db, `INSERT INTO tenants (id, name, slug) VALUES ($1,$2,$3)`, id.String(), "sa-"+id.String(), "sa-"+id.String())
		tid := id
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.Background(), `DELETE FROM asset_relationships WHERE tenant_id = $1`, tid.String())
			_, _ = db.ExecContext(context.Background(), `DELETE FROM assets WHERE tenant_id = $1`, tid.String())
			_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, tid.String())
		})
	}
	add := func(tenant shared.ID, name, typ string) shared.ID {
		id := shared.NewID()
		mustExec(t, db, `INSERT INTO assets (id, tenant_id, name, asset_type, properties) VALUES ($1,$2,$3,$4,'{"asn_org":"Example Hosting"}'::jsonb)`,
			id.String(), tenant.String(), name, typ)
		return id
	}
	edge := func(tenant, from, to shared.ID) {
		mustExec(t, db, `INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES ($1,$2,$3,'resolves_to')`,
			tenant.String(), from.String(), to.String())
	}
	ip := add(org, "203.0.113.30", "ip_address")
	a, b := add(org, "a.sa.example", "domain"), add(org, "b.sa.example", "subdomain")
	edge(org, a, ip)
	edge(org, b, ip)
	gone := add(org, "gone.sa.example", "domain")
	edge(org, gone, ip)
	mustExec(t, db, `UPDATE assets SET deleted_at = NOW() WHERE id = $1`, gone.String())
	oip, on := add(other, "203.0.113.31", "ip_address"), add(other, "x.other.example", "domain")
	edge(other, on, oip)

	got, err := repo.ResolvedAddresses(ctx, org, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Address != "203.0.113.30" || got[0].AssetID != ip.String() || got[0].Properties["asn_org"] != "Example Hosting" {
		t.Fatalf("addresses %+v", got)
	}
	names := map[string]string{}
	for _, n := range got[0].Names {
		names[n.Name] = n.AssetID
	}
	if len(names) != 2 || names["a.sa.example"] != a.String() || names["b.sa.example"] != b.String() {
		t.Fatalf("names %v, want a and b paired with their own ids (deleted one left out)", names)
	}
}
