package integration

// Migration 001212: an active automation that uses a refused trigger
// (finding_updated, webhook) or action (trigger_pipeline) is switched off;
// one that uses only supported types stays on. Runs in a rolled-back
// transaction.

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestMigration001212SwitchesOffRefusedAutomations(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenant := seedLifecycleTenant(ctx, t, db)

	up, err := os.ReadFile("../../migrations/001212_automations_refused_types_inactive.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(up)), "insert into") {
		t.Fatal("the migration must not insert rows (no SQL audit rows)")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}

	// automation inserts an active automation with one node per config.
	automation := func(configs ...string) string {
		t.Helper()
		id := shared.NewID().String()
		exec(`INSERT INTO workflows (id, tenant_id, name, is_active) VALUES ($1, $2, $3, true)`, id, tenant.String(), "automation "+id)
		for i, c := range configs {
			nodeType := "action"
			if strings.Contains(c, "trigger_type") {
				nodeType = "trigger"
			}
			exec(`INSERT INTO workflow_nodes (workflow_id, node_key, node_type, name, config) VALUES ($1, $2, $3, 'n', $4::jsonb)`,
				id, nodeType+string(rune('a'+i)), nodeType, c)
		}
		return id
	}
	webhook := automation(`{"trigger_type":"webhook"}`, `{"action_type":"add_tags"}`)
	updated := automation(`{"trigger_type":"finding_updated"}`)
	pipeline := automation(`{"trigger_type":"finding_created"}`,
		`{"action_type":"trigger_pipeline","action_config":{"pipeline_id":"00000000-0000-0000-0000-000000000001"}}`)
	fine := automation(`{"trigger_type":"finding_created"}`, `{"action_type":"trigger_scan"}`)

	exec(string(up))

	active := func(id string) bool {
		t.Helper()
		var on bool
		if err := tx.QueryRowContext(ctx, `SELECT is_active FROM workflows WHERE id = $1`, id).Scan(&on); err != nil {
			t.Fatal(err)
		}
		return on
	}
	for name, id := range map[string]string{"webhook": webhook, "finding_updated": updated, "trigger_pipeline": pipeline} {
		if active(id) {
			t.Errorf("automation using %s is still active", name)
		}
	}
	if !active(fine) {
		t.Error("automation using only supported types was switched off")
	}

	// The rows stay: nothing was deleted.
	var nodes int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM workflow_nodes WHERE workflow_id = $1`, pipeline).Scan(&nodes); err != nil {
		t.Fatal(err)
	}
	if nodes != 2 {
		t.Fatalf("trigger_pipeline automation has %d nodes, want 2", nodes)
	}
}
