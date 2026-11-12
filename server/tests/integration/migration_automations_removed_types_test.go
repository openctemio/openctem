package integration

// Migration automations_removed_types: every automation that holds a node of
// a removed type (trigger, action or notification) is switched off with
// disabled_reason = uses_removed_type, nothing is deleted, stored
// http_request headers are dropped, and automations of known types are
// untouched. Down drops the column; up again works.

import (
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigrationAutomationsRemovedTypes(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migautorm", dir)
	v := testdb.MigrationVersion(t, dir, "automations_removed_types")
	testdb.Migrate(t, db, dir, v, v, true)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const (
		tenant   = "a1111111-1111-4111-8111-111111111131"
		okAuto   = "b2222222-2222-4222-8222-222222222231"
		httpAuto = "b2222222-2222-4222-8222-222222222232"
		schedOff = "b2222222-2222-4222-8222-222222222233"
		pdAuto   = "b2222222-2222-4222-8222-222222222234"
	)
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'a', 'mig-autorm-a')`, tenant)
	exec(`INSERT INTO automations (id, tenant_id, name, is_active) VALUES
		($1, $5, 'ok', true), ($2, $5, 'http', true), ($3, $5, 'sched', false), ($4, $5, 'pd', true)`,
		okAuto, httpAuto, schedOff, pdAuto, tenant)
	exec(`INSERT INTO automation_nodes (automation_id, node_key, node_type, name, config) VALUES
		($1, 't', 'trigger', 't', '{"trigger_type":"finding_created"}'),
		($1, 'a', 'action', 'a', '{"action_type":"add_tags","action_config":{"tags":["x"]}}'),
		($2, 't', 'trigger', 't', '{"trigger_type":"manual"}'),
		($2, 'a', 'action', 'a', '{"action_type":"http_request","action_config":{"url":"https://hooks.example.com","headers":{"Authorization":"Bearer s3cr3t"}}}'),
		($3, 't', 'trigger', 't', '{"trigger_type":"schedule"}'),
		($4, 't', 'trigger', 't', '{"trigger_type":"manual"}'),
		($4, 'n', 'notification', 'n', '{"notification_type":"pagerduty"}')`,
		okAuto, httpAuto, schedOff, pdAuto)

	testdb.Migrate(t, db, dir, v, v, false)

	check := func(id string, wantActive bool, wantReason string) {
		t.Helper()
		var active bool
		var reason *string
		if err := db.QueryRow(`SELECT is_active, disabled_reason FROM automations WHERE id = $1`, id).Scan(&active, &reason); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		got := ""
		if reason != nil {
			got = *reason
		}
		if active != wantActive || got != wantReason {
			t.Fatalf("%s: active=%v reason=%q, want %v %q", id, active, got, wantActive, wantReason)
		}
	}
	check(okAuto, true, "")
	check(httpAuto, false, "uses_removed_type")
	check(schedOff, false, "uses_removed_type")
	check(pdAuto, false, "uses_removed_type")

	var nodes int
	if err := db.QueryRow(`SELECT count(*) FROM automation_nodes WHERE automation_id = ANY($1)`,
		"{"+okAuto+","+httpAuto+","+schedOff+","+pdAuto+"}").Scan(&nodes); err != nil || nodes != 7 {
		t.Fatalf("nodes kept = %d (%v), want 7: nothing is deleted", nodes, err)
	}
	var hasHeaders bool
	var url string
	if err := db.QueryRow(`SELECT config->'action_config' ? 'headers', config->'action_config'->>'url'
		FROM automation_nodes WHERE automation_id = $1 AND node_key = 'a'`, httpAuto).Scan(&hasHeaders, &url); err != nil {
		t.Fatal(err)
	}
	if hasHeaders || url != "https://hooks.example.com" {
		t.Fatalf("http_request headers kept=%v url=%q: headers must go, the rest stays", hasHeaders, url)
	}

	if _, err := db.Exec(`UPDATE automations SET disabled_reason = 'something_else' WHERE id = $1`, okAuto); err == nil {
		t.Fatal("an unknown disabled_reason was stored")
	}

	testdb.Migrate(t, db, dir, v, v, true)
	var col int
	if err := db.QueryRow(`SELECT count(*) FROM information_schema.columns WHERE table_name = 'automations' AND column_name = 'disabled_reason'`).Scan(&col); err != nil || col != 0 {
		t.Fatalf("down left disabled_reason (%d, %v)", col, err)
	}
	testdb.Migrate(t, db, dir, v, v, false)
}
