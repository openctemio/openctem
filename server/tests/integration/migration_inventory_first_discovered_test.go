package integration

// Migration inventory_first_discovered (research/124, RFC-054 §15): automatic
// needs_review records move into the inventory as discovered; a person's
// needs_review, every other state and a tenant that keeps the review gate
// are left alone; down restores needs_review; up again is idempotent.
//
// Runs on a private database: everything up, this migration down, seed, up.

import (
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigrationInventoryFirstDiscovered(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "miginvfirst", dir)
	v := testdb.MigrationVersion(t, dir, "inventory_first_discovered")
	testdb.Migrate(t, db, dir, v, v, true)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const (
		tenantA = "a1111111-1111-4111-8111-111111111111"
		tenantG = "c3333333-3333-4333-8333-333333333333" // keeps the review gate
		auto    = "01000000-0000-4000-8000-000000000001"
		person  = "01000000-0000-4000-8000-000000000002"
		cand    = "01000000-0000-4000-8000-000000000003"
		conf    = "01000000-0000-4000-8000-000000000004"
		rej     = "01000000-0000-4000-8000-000000000005"
		child   = "01000000-0000-4000-8000-000000000006"
		gated   = "03000000-0000-4000-8000-000000000001"
	)
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'a', 'mig-invfirst-a')`, tenantA)
	exec(`INSERT INTO tenants (id, name, slug, settings) VALUES ($1, 'g', 'mig-invfirst-g', '{"scope":{"review_before_inventory":true}}')`, tenantG)
	asset := func(id, tenant, name, typ string) {
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, $4, 'active')`, id, tenant, name, typ)
	}
	attr := func(id, tenant, state string, human bool) {
		if human {
			exec(`INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence, decided_at) VALUES ($1, $2, $3, 100, now())`, id, tenant, state)
			return
		}
		exec(`INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence) VALUES ($1, $2, $3, 60)`, id, tenant, state)
	}
	asset(auto, tenantA, "198.51.100.1", "ip_address")
	asset(person, tenantA, "held.example.com", "subdomain")
	asset(cand, tenantA, "cand.example.com", "subdomain")
	asset(conf, tenantA, "ok.example.com", "subdomain")
	asset(rej, tenantA, "no.example.com", "subdomain")
	asset(child, tenantA, "198.51.100.1:443:tcp", "service")
	asset(gated, tenantG, "198.51.100.1", "ip_address")
	attr(auto, tenantA, "needs_review", false)
	attr(person, tenantA, "needs_review", true)
	attr(cand, tenantA, "candidate", false)
	attr(conf, tenantA, "confirmed", false)
	attr(rej, tenantA, "rejected", true)
	attr(child, tenantA, "needs_review", false)
	exec(`UPDATE asset_attributions SET follows_host_id = $1 WHERE asset_id = $2`, auto, child)
	attr(gated, tenantG, "needs_review", false)

	check := func() {
		t.Helper()
		want := map[string]string{
			auto: "discovered", child: "discovered", person: "needs_review", cand: "candidate",
			conf: "confirmed", rej: "rejected", gated: "needs_review",
		}
		for id, w := range want {
			var state string
			if err := db.QueryRow(`SELECT state FROM asset_attributions WHERE asset_id = $1`, id).Scan(&state); err != nil {
				t.Fatal(err)
			}
			if state != w {
				t.Errorf("%s state %s, want %s", id, state, w)
			}
		}
	}
	testdb.Migrate(t, db, dir, v, v, false)
	check()

	// Down restores needs_review; up again gives the same result.
	testdb.Migrate(t, db, dir, v, v, true)
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM asset_attributions WHERE state = 'needs_review'`).Scan(&n); err != nil || n != 4 {
		t.Fatalf("after down: %d needs_review (%v), want 4", n, err)
	}
	testdb.Migrate(t, db, dir, v, v, false)
	check()
}
