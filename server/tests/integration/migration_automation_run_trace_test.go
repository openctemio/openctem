package integration

// Migration automation_run_trace: run steps get in/out/skipped counts;
// automation_deliveries refuses a simulated delivery marked sent (and a live
// one marked simulated) and a second delivery with the same key; deliveries
// go with their run. Down and up again work.

import (
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigrationAutomationRunTrace(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migautotrace", dir)
	v := testdb.MigrationVersion(t, dir, "automation_run_trace")

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const (
		tenant = "a1111111-1111-4111-8111-111111111151"
		auto   = "b2222222-2222-4222-8222-222222222251"
		run    = "d4444444-4444-4444-8444-444444444451"
	)
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'a', 'mig-autotrace-a')`, tenant)
	exec(`INSERT INTO automations (id, tenant_id, name) VALUES ($1, $2, 'a')`, auto, tenant)
	exec(`INSERT INTO automation_runs (id, automation_id, tenant_id, trigger_type, status, mode) VALUES ($1, $2, $3, 'manual', 'completed', 'simulate')`, run, auto, tenant)
	exec(`INSERT INTO automation_run_steps (automation_run_id, node_id, node_key, node_type, in_count, out_count, skipped)
		VALUES ($1, gen_random_uuid(), 'a', 'action', 1, 0, '{"no_change":1}')`, run)

	insert := func(key, mode, status string) error {
		_, err := db.Exec(`INSERT INTO automation_deliveries (tenant_id, run_id, node_key, channel, mode, status, idempotency_key)
			VALUES ($1, $2, 'n', 'slack', $3, $4, $5)`, tenant, run, mode, status, key)
		return err
	}
	if err := insert("k1", "simulate", "simulated"); err != nil {
		t.Fatal(err)
	}
	if insert("k2", "simulate", "sent") == nil || insert("k3", "live", "simulated") == nil {
		t.Fatal("a simulated delivery marked sent, or a live one marked simulated, was stored")
	}
	if insert("k1", "simulate", "simulated") == nil {
		t.Fatal("a second delivery with the same key was stored")
	}
	exec(`DELETE FROM automation_runs WHERE id = $1`, run)
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM automation_deliveries WHERE run_id = $1`, run).Scan(&n); err != nil || n != 0 {
		t.Fatalf("deliveries left after their run was deleted: %d (%v)", n, err)
	}

	testdb.Migrate(t, db, dir, v, v, true)
	testdb.Migrate(t, db, dir, v, v, false)
}
