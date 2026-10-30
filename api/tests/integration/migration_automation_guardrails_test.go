package integration

// Migration automation_guardrails: an automation whose draft or published
// version sets a closing status is switched off, back to simulate, with
// disabled_reason status_not_allowed; one that sets confirmed is untouched;
// runs may be paused (blast_radius); the cap is bounded. Down and up again.

import (
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigrationAutomationGuardrails(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migautoguard", dir)
	v := testdb.MigrationVersion(t, dir, "automation_guardrails")
	testdb.Migrate(t, db, dir, v, v, true)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const (
		tenant  = "a1111111-1111-4111-8111-111111111171"
		closing = "b2222222-2222-4222-8222-222222222271"
		fine    = "b2222222-2222-4222-8222-222222222272"
		viaVer  = "b2222222-2222-4222-8222-222222222273"
		ver     = "c3333333-3333-4333-8333-333333333373"
	)
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'a', 'mig-autoguard-a')`, tenant)
	exec(`INSERT INTO automations (id, tenant_id, name, is_active, mode) VALUES ($1, $4, 'c', true, 'simulate'), ($2, $4, 'f', true, 'simulate'), ($3, $4, 'v', true, 'simulate')`, closing, fine, viaVer, tenant)
	exec(`INSERT INTO automation_nodes (automation_id, node_key, node_type, name, config) VALUES
		($1, 's', 'action', 's', '{"action_type":"update_status","action_config":{"status":"resolved"}}'),
		($2, 's', 'action', 's', '{"action_type":"update_status","action_config":{"status":"confirmed"}}'),
		($3, 's', 'action', 's', '{"action_type":"update_status","action_config":{"status":"confirmed"}}')`, closing, fine, viaVer)
	exec(`INSERT INTO automation_versions (id, tenant_id, automation_id, version, definition, digest, risk_class, status)
		VALUES ($1, $2, $3, 1, '{"nodes":[{"node_key":"s","config":{"action_type":"update_status","action_config":{"status":"false_positive"}}}]}', 'x', 'elevated', 'published')`, ver, tenant, viaVer)
	exec(`UPDATE automations SET mode = 'live', published_version_id = $2 WHERE id = $1`, viaVer, ver)

	testdb.Migrate(t, db, dir, v, v, false)

	check := func(id string, active bool, mode, reason string) {
		t.Helper()
		var a bool
		var m string
		var r *string
		if err := db.QueryRow(`SELECT is_active, mode, disabled_reason FROM automations WHERE id = $1`, id).Scan(&a, &m, &r); err != nil {
			t.Fatal(err)
		}
		got := ""
		if r != nil {
			got = *r
		}
		if a != active || m != mode || got != reason {
			t.Fatalf("%s = active %v mode %s reason %q, want %v %s %q", id, a, m, got, active, mode, reason)
		}
	}
	check(closing, false, "simulate", "status_not_allowed")
	check(fine, true, "simulate", "")
	check(viaVer, false, "simulate", "status_not_allowed")

	if _, err := db.Exec(`UPDATE automations SET max_changes_per_run = 1001 WHERE id = $1`, fine); err == nil {
		t.Fatal("a cap above 1000 was stored")
	}
	exec(`INSERT INTO automation_runs (automation_id, tenant_id, trigger_type, status, pause_reason) VALUES ($1, $2, 'manual', 'paused', 'blast_radius')`, fine, tenant)

	testdb.Migrate(t, db, dir, v, v, true)
	var st string
	if err := db.QueryRow(`SELECT status FROM automation_runs WHERE automation_id = $1`, fine).Scan(&st); err != nil || st != "failed" {
		t.Fatalf("paused run after down = %q (%v), want failed", st, err)
	}
	testdb.Migrate(t, db, dir, v, v, false)
}
