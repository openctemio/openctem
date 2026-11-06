package postgres

import (
	"context"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The suggestion card reads on the real schema: addresses that names resolve
// to, without addresses a person ruled out, narrowed to the caller's data
// scope (rows and the names shown), never another tenant's; confirmed-by-a-
// person assets. Requires DATABASE_URL.
func TestEASMSuggestionReads(t *testing.T) {
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
	www := asset(tenant, "www.sugg.example", "subdomain")
	api := asset(tenant, "API.sugg.example", "subdomain")
	ipPending := asset(tenant, "198.51.100.30", "ip_address")
	ipNoRecord := asset(tenant, "198.51.100.31", "ip_address")
	ipRejected := asset(tenant, "198.51.100.32", "ip_address")
	ipMonitor := asset(tenant, "198.51.100.33", "ip_address")
	ipLonely := asset(tenant, "198.51.100.34", "ip_address") // no name resolves to it
	for _, ip := range []string{ipPending, ipNoRecord, ipRejected, ipMonitor} {
		resolves(tenant, www, ip)
	}
	resolves(tenant, api, ipPending)
	_ = ipLonely
	if err := repo.SaveAutomatic(ctx, tenant, ipPending, attribution.Decision{State: attribution.StateNeedsReview, Confidence: 60}); err != nil {
		t.Fatal(err)
	}
	for id, st := range map[string]attribution.State{ipRejected: attribution.StateRejected, ipMonitor: attribution.StateMonitorOnly} {
		if _, err := repo.SaveDecision(ctx, tenant, id, st, ""); err != nil {
			t.Fatal(err)
		}
	}
	// Tenant B: same address, its own name.
	bName := asset(other, "b.sugg.example", "subdomain")
	bIP := asset(other, "198.51.100.30", "ip_address")
	resolves(other, bName, bIP)

	// Ports: services on the address and on its names; tenant B's service
	// on its own address of the same text never shows.
	service := func(tid shared.ID, assetID string, port int) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO asset_services (tenant_id, asset_id, port) VALUES ($1, $2, $3)`,
			tid.String(), assetID, port); err != nil {
			t.Fatal(err)
		}
	}
	service(tenant, ipPending, 22)
	service(tenant, api, 8443)
	service(tenant, www, 443)
	service(other, bIP, 3389)

	rows, err := repo.AddressesBehindNames(ctx, tenant, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.AssetID == ipPending && !slices.Equal(r.Ports, []int{22, 443, 8443}) {
			t.Fatalf("ports %v", r.Ports)
		}
		if r.FirstSeen.IsZero() {
			t.Fatalf("first seen not read for %s", r.AssetID)
		}
	}
	got := map[string][]string{}
	for _, r := range rows {
		got[r.AssetID] = r.VisibleNames
	}
	if len(got) != 2 || !slices.Equal(got[ipPending], []string{"api.sugg.example", "www.sugg.example"}) || len(got[ipNoRecord]) != 1 {
		t.Fatalf("addresses %v (rejected, monitor-only and unresolved addresses must be left out)", got)
	}

	// A restricted caller sees only its own address rows, and only its own
	// names with them; every name still counts for shared hosting.
	user := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'scoped')`, user.String(), user.String()+"@sugg.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.String()) })
	if _, err := db.ExecContext(ctx, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3), ($1, $2, $4)`,
		user.String(), tenant.String(), ipPending, www); err != nil {
		t.Fatal(err)
	}
	rows, err = repo.AddressesBehindNames(ctx, tenant, &shared.DataScope{TenantID: tenant, UserID: user}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].AssetID != ipPending || !slices.Equal(rows[0].VisibleNames, []string{"www.sugg.example"}) || len(rows[0].AllNames) != 2 {
		t.Fatalf("restricted rows %+v", rows)
	}
	// A restricted caller sees the ports of its own names only.
	if !slices.Equal(rows[0].Ports, []int{22, 443}) {
		t.Fatalf("restricted ports %v", rows[0].Ports)
	}

	// Another tenant: only its own address and name.
	rows, err = repo.AddressesBehindNames(ctx, other, nil, 100)
	if err != nil || len(rows) != 1 || rows[0].AssetID != bIP || !slices.Equal(rows[0].VisibleNames, []string{"b.sugg.example"}) {
		t.Fatalf("tenant B rows %+v %v", rows, err)
	}

	// Confirmed by a person: only person decisions, only the tenant's.
	conf := asset(tenant, "conf.sugg.example", "subdomain")
	if _, err := repo.SaveDecision(ctx, tenant, conf, attribution.StateConfirmed, ""); err != nil {
		t.Fatal(err)
	}
	auto := asset(tenant, "auto.sugg.example", "subdomain")
	if err := repo.SaveAutomatic(ctx, tenant, auto, attribution.Decision{State: attribution.StateConfirmed, Confidence: 99}); err != nil {
		t.Fatal(err)
	}
	bConf := asset(other, "conf-b.sugg.example", "subdomain")
	if _, err := repo.SaveDecision(ctx, other, bConf, attribution.StateConfirmed, ""); err != nil {
		t.Fatal(err)
	}
	cs, err := repo.ConfirmedByPerson(ctx, tenant, nil, 100)
	if err != nil || len(cs) != 1 || cs[0].AssetID != conf || cs[0].TargetType != "domain" {
		t.Fatalf("confirmed %+v %v", cs, err)
	}
	if cs, err = repo.ConfirmedByPerson(ctx, tenant, &shared.DataScope{TenantID: tenant, UserID: user}, 100); err != nil || len(cs) != 0 {
		t.Fatalf("restricted confirmed %+v %v", cs, err)
	}
}
