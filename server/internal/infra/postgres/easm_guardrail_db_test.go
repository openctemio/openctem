package postgres

import (
	"context"
	"slices"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// The guardrail reads (RFC-054 §16) on the real schema: names resolving to
// an address and the addresses behind a name, never another tenant's, never
// a deleted asset's. Requires DATABASE_URL.
func TestEASMGuardrailReads(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewAttributionRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	asset := func(tid shared.ID, name, typ string) string {
		t.Helper()
		id := shared.NewID().String()
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, $4, 'active')`,
			id, tid.String(), name, typ); err != nil {
			t.Fatal(err)
		}
		return id
	}
	resolves := func(tid shared.ID, name, ip string) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type)
			VALUES ($1, $2, $3, 'resolves_to')`, tid.String(), name, ip); err != nil {
			t.Fatal(err)
		}
	}
	www := asset(tenant, "www.guard.example", "subdomain")
	mail := asset(tenant, "mail.guard.example", "subdomain")
	gone := asset(tenant, "gone.guard.example", "subdomain")
	ip := asset(tenant, "198.51.100.60", "ip_address")
	ip2 := asset(tenant, "198.51.100.61", "ip_address")
	resolves(tenant, www, ip)
	resolves(tenant, mail, ip)
	resolves(tenant, www, ip2)
	resolves(tenant, gone, ip)
	if _, err := db.ExecContext(ctx, `UPDATE assets SET deleted_at = now() WHERE id = $1`, gone); err != nil {
		t.Fatal(err)
	}
	// A name served by a provider: a dedicated address by edge, the shared
	// one only on the name's recorded addresses (research/531). A recorded
	// address that is not a shared one is not read as a dedicated address.
	setProps := func(id, props string) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `UPDATE assets SET properties = $2::jsonb WHERE id = $1`, id, props); err != nil {
			t.Fatal(err)
		}
	}
	cdn := asset(tenant, "cdn.guard.example", "subdomain")
	resolves(tenant, cdn, asset(tenant, "198.51.100.63", "ip_address"))
	setProps(cdn, `{"ip_addresses": ["104.16.1.1", "198.51.100.62"]}`)
	goneCDN := asset(tenant, "gone-cdn.guard.example", "subdomain")
	setProps(goneCDN, `{"ip_addresses": ["104.16.1.1"]}`)
	if _, err := db.ExecContext(ctx, `UPDATE assets SET deleted_at = now() WHERE id = $1`, goneCDN); err != nil {
		t.Fatal(err)
	}
	// Tenant B: its own name on the same address text.
	bName := asset(other, "b.guard.example", "subdomain")
	bIP := asset(other, "198.51.100.60", "ip_address")
	resolves(other, bName, bIP)
	setProps(asset(other, "cdn.guard.example", "subdomain"), `{"ip_addresses": ["104.16.1.1"]}`)

	names, err := repo.NamesResolvingTo(ctx, tenant, []string{ip, bIP})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names[ip], []string{"mail.guard.example", "www.guard.example"}) || len(names) != 1 {
		t.Fatalf("names resolving to: %v (deleted names and another tenant's address must be left out)", names)
	}
	addrs, err := repo.AddressesOf(ctx, tenant, []string{" WWW.guard.example ", "b.guard.example", "gone.guard.example", "cdn.guard.example", "gone-cdn.guard.example"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(addrs["www.guard.example"], []string{"198.51.100.60", "198.51.100.61"}) ||
		!slices.Equal(addrs["cdn.guard.example"], []string{"198.51.100.63", "104.16.1.1"}) || len(addrs) != 2 {
		t.Fatalf("addresses of: %v", addrs)
	}
	if x, _ := repo.AddressesOf(ctx, other, []string{"www.guard.example"}); len(x) != 0 {
		t.Fatalf("another tenant reads this tenant's names: %v", x)
	}
	if x, _ := repo.AddressesOf(ctx, other, []string{"cdn.guard.example"}); !slices.Equal(x["cdn.guard.example"], []string{"104.16.1.1"}) || len(x) != 1 {
		t.Fatalf("tenant B reads its own name only: %v", x)
	}
}
