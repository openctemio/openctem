package postgres

import (
	"context"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// OpenPortsOfNames on the real schema: the live open TCP ports of the live
// addresses a name resolves to; never a closed port, a UDP port, a deleted
// address, or another tenant's rows. Requires DATABASE_URL.
func TestOpenPortsOfNames(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewAttributionRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	asset := func(tid shared.ID, name, typ, sub, status, props string) string {
		t.Helper()
		id := shared.NewID().String()
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, status, properties)
			VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7::jsonb)`, id, tid.String(), name, typ, sub, status, props); err != nil {
			t.Fatal(err)
		}
		return id
	}
	edge := func(tid shared.ID, src, dst, typ string) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type)
			VALUES ($1, $2, $3, $4)`, tid.String(), src, dst, typ); err != nil {
			t.Fatal(err)
		}
	}
	port := func(tid shared.ID, ip, name, status, props string) {
		t.Helper()
		edge(tid, ip, asset(tid, name, "service", "open_port", status, props), "exposes")
	}
	www := asset(tenant, "WWW.ports.example", "subdomain", "", "active", "{}")
	ip := asset(tenant, "198.51.100.70", "ip_address", "", "active", "{}")
	gone := asset(tenant, "198.51.100.71", "ip_address", "", "active", "{}")
	edge(tenant, www, ip, "resolves_to")
	edge(tenant, www, gone, "resolves_to")
	port(tenant, ip, "198.51.100.70:8443:tcp", "active", `{"port": 8443, "protocol": "tcp"}`)
	port(tenant, ip, "198.51.100.70:22:tcp", "active", `{"port": 22}`)
	port(tenant, ip, "198.51.100.70:8080:tcp", "inactive", `{"port": 8080, "protocol": "tcp"}`)
	port(tenant, ip, "198.51.100.70:53:udp", "active", `{"port": 53, "protocol": "udp"}`)
	port(tenant, gone, "198.51.100.71:9443:tcp", "active", `{"port": 9443, "protocol": "tcp"}`)
	if _, err := db.ExecContext(ctx, `UPDATE assets SET deleted_at = now() WHERE id = $1`, gone); err != nil {
		t.Fatal(err)
	}
	// Tenant B: the same name with its own address and port.
	bName := asset(other, "www.ports.example", "subdomain", "", "active", "{}")
	bIP := asset(other, "198.51.100.70", "ip_address", "", "active", "{}")
	edge(other, bName, bIP, "resolves_to")
	port(other, bIP, "198.51.100.70:3389:tcp", "active", `{"port": 3389, "protocol": "tcp"}`)

	got, err := repo.OpenPortsOfNames(ctx, tenant, []string{"www.ports.example", "nothing.ports.example"})
	if err != nil {
		t.Fatal(err)
	}
	ps := got["www.ports.example"]
	slices.Sort(ps)
	if !slices.Equal(ps, []int{22, 8443}) || len(got) != 1 {
		t.Fatalf("open ports of names: %v", got)
	}
	b, err := repo.OpenPortsOfNames(ctx, other, []string{"www.ports.example"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(b["www.ports.example"], []int{3389}) {
		t.Fatalf("tenant B reads: %v", b)
	}
}
