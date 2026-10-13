package integration

// Migration attribution_children_follow_host: the one-time backfill links
// pending automatic children (services by exposes, certificates by
// serves_certificate through their service) to their pending host, changes
// no state, never links across tenants, never links a child with two hosts
// or one a person decided, and is idempotent.
//
// Runs on a private database: everything up, this migration down, seed, up.

import (
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigrationAttributionChildrenFollowHost(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migfollowhost", dir)
	v := testdb.MigrationVersion(t, dir, "attribution_children_follow_host")
	testdb.Migrate(t, db, dir, v, v, true)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const (
		tenantA = "a1111111-1111-4111-8111-111111111111"
		tenantB = "b2222222-2222-4222-8222-222222222222"
		ip      = "01000000-0000-4000-8000-000000000001"
		svc     = "01000000-0000-4000-8000-000000000002"
		cert    = "01000000-0000-4000-8000-000000000003"
		okIP    = "01000000-0000-4000-8000-000000000004" // confirmed host
		okSvc   = "01000000-0000-4000-8000-000000000005"
		decided = "01000000-0000-4000-8000-000000000006" // a person decided the child
		ip2     = "01000000-0000-4000-8000-000000000007"
		svc2    = "01000000-0000-4000-8000-000000000008"
		twoHost = "01000000-0000-4000-8000-000000000009" // cert served by svc and svc2
		bIP     = "02000000-0000-4000-8000-000000000001"
		bSvc    = "02000000-0000-4000-8000-000000000002"
	)
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'a', 'mig-follow-a'), ($2, 'b', 'mig-follow-b')`, tenantA, tenantB)
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
	edge := func(tenant, src, dst, typ string) {
		exec(`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES ($1, $2, $3, $4)`,
			tenant, src, dst, typ)
	}
	asset(ip, tenantA, "198.51.100.1", "ip_address")
	asset(svc, tenantA, "198.51.100.1:443", "service")
	asset(cert, tenantA, "c0ffee", "certificate")
	asset(okIP, tenantA, "198.51.100.2", "ip_address")
	asset(okSvc, tenantA, "198.51.100.2:443", "service")
	asset(decided, tenantA, "198.51.100.1:22", "service")
	asset(ip2, tenantA, "198.51.100.3", "ip_address")
	asset(svc2, tenantA, "198.51.100.3:443", "service")
	asset(twoHost, tenantA, "beef", "certificate")
	asset(bIP, tenantB, "198.51.100.1", "ip_address")
	asset(bSvc, tenantB, "198.51.100.1:443", "service")
	attr(ip, tenantA, "needs_review", false)
	attr(svc, tenantA, "needs_review", false)
	attr(cert, tenantA, "candidate", false)
	attr(okIP, tenantA, "confirmed", false)
	attr(okSvc, tenantA, "needs_review", false)
	attr(decided, tenantA, "needs_review", true)
	attr(ip2, tenantA, "needs_review", false)
	attr(svc2, tenantA, "needs_review", false)
	attr(twoHost, tenantA, "needs_review", false)
	attr(bIP, tenantB, "needs_review", false)
	attr(bSvc, tenantB, "needs_review", false)
	edge(tenantA, ip, svc, "exposes")
	edge(tenantA, svc, cert, "serves_certificate")
	edge(tenantA, okIP, okSvc, "exposes")
	edge(tenantA, ip, decided, "exposes")
	edge(tenantA, ip2, svc2, "exposes")
	edge(tenantA, svc, twoHost, "serves_certificate")
	edge(tenantA, svc2, twoHost, "serves_certificate")
	edge(tenantB, bIP, bSvc, "exposes")

	check := func() {
		t.Helper()
		want := map[string]string{svc: ip, cert: ip, svc2: ip2, okSvc: "", decided: "", twoHost: "", ip: "", bSvc: bIP}
		states := map[string]string{svc: "needs_review", cert: "candidate", okSvc: "needs_review", decided: "needs_review"}
		for id, host := range want {
			var follows sql.NullString
			var state string
			if err := db.QueryRow(`SELECT follows_host_id, state FROM asset_attributions WHERE asset_id = $1`, id).Scan(&follows, &state); err != nil {
				t.Fatal(err)
			}
			if follows.String != host {
				t.Errorf("%s follows %q, want %q", id, follows.String, host)
			}
			if s, ok := states[id]; ok && s != state {
				t.Errorf("%s state %s, want %s (the backfill changes no state)", id, state, s)
			}
		}
		// Every link stays inside its tenant.
		var cross int
		if err := db.QueryRow(`SELECT count(*) FROM asset_attributions c JOIN assets h ON h.id = c.follows_host_id
			WHERE h.tenant_id <> c.tenant_id`).Scan(&cross); err != nil || cross != 0 {
			t.Fatalf("cross-tenant links: %d %v", cross, err)
		}
	}
	testdb.Migrate(t, db, dir, v, v, false)
	check()
	// Down and up again: the same result (idempotent backfill).
	testdb.Migrate(t, db, dir, v, v, true)
	testdb.Migrate(t, db, dir, v, v, false)
	check()
}
