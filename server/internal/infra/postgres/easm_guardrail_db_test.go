package postgres

import (
	"context"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
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
	www := asset(tenant, "WWW.guard.example", "subdomain")
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
	// Tenant B: its own name on the same address text.
	bName := asset(other, "b.guard.example", "subdomain")
	bIP := asset(other, "198.51.100.60", "ip_address")
	resolves(other, bName, bIP)

	names, err := repo.NamesResolvingTo(ctx, tenant, []string{ip, bIP})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names[ip], []string{"mail.guard.example", "www.guard.example"}) || len(names) != 1 {
		t.Fatalf("names resolving to: %v (deleted names and another tenant's address must be left out)", names)
	}
	addrs, err := repo.AddressesOf(ctx, tenant, []string{"www.guard.example", "b.guard.example", "gone.guard.example"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(addrs["www.guard.example"], []string{"198.51.100.60", "198.51.100.61"}) || len(addrs) != 1 {
		t.Fatalf("addresses of: %v", addrs)
	}
	if x, _ := repo.AddressesOf(ctx, other, []string{"www.guard.example"}); len(x) != 0 {
		t.Fatalf("another tenant reads this tenant's names: %v", x)
	}
}
