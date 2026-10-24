package integration

// Migration automation_versions: an automation that is switched on becomes
// version 1, published by its owner, mode live, with its graph as the
// definition and a risk class from its steps; one that is off stays in
// simulate without a version; existing runs are live; run steps no longer
// reference the draft's nodes. Down and up again work.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	automationdom "github.com/openctemio/openctem/api/pkg/domain/automation"
)

func TestMigrationAutomationVersions(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migautover", dir)
	v := testdb.MigrationVersion(t, dir, "automation_versions")
	testdb.Migrate(t, db, dir, v, v, true)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const (
		tenant = "a1111111-1111-4111-8111-111111111141"
		owner  = "c3333333-3333-4333-8333-333333333341"
		on     = "b2222222-2222-4222-8222-222222222241"
		off    = "b2222222-2222-4222-8222-222222222242"
		scan   = "b2222222-2222-4222-8222-222222222243"
		run    = "d4444444-4444-4444-8444-444444444441"
	)
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'a', 'mig-autover-a')`, tenant)
	exec(`INSERT INTO users (id, email, name) VALUES ($1, 'owner@autover.test', 'o')`, owner)
	exec(`INSERT INTO automations (id, tenant_id, name, is_active, created_by) VALUES
		($1, $4, 'on', true, $5), ($2, $4, 'off', false, $5), ($3, $4, 'scan', true, $5)`, on, off, scan, tenant, owner)
	exec(`INSERT INTO automation_nodes (automation_id, node_key, node_type, name, config) VALUES
		($1, 't', 'trigger', 't', '{"trigger_type":"finding_created"}'),
		($1, 'a', 'action', 'a', '{"action_type":"update_status","action_config":{"status":"confirmed"}}'),
		($2, 't', 'trigger', 't', '{"trigger_type":"manual"}'),
		($3, 't', 'trigger', 't', '{"trigger_type":"manual"}'),
		($3, 's', 'action', 's', '{"action_type":"trigger_scan"}')`, on, off, scan)
	exec(`INSERT INTO automation_edges (automation_id, source_node_key, target_node_key) VALUES ($1, 't', 'a')`, on)
	exec(`INSERT INTO automation_runs (id, automation_id, tenant_id, trigger_type, status) VALUES ($1, $2, $3, 'manual', 'completed')`, run, on, tenant)

	testdb.Migrate(t, db, dir, v, v, false)

	type row struct {
		mode, risk, status, by string
		version                int
		def                    []byte
	}
	get := func(id string) (row, bool) {
		t.Helper()
		var r row
		err := db.QueryRow(`SELECT a.mode, COALESCE(v.risk_class, ''), COALESCE(v.status, ''), COALESCE(v.published_by::text, ''),
			COALESCE(v.version, 0), COALESCE(v.definition, 'null'::jsonb)
			FROM automations a LEFT JOIN automation_versions v ON v.id = a.published_version_id WHERE a.id = $1`, id).
			Scan(&r.mode, &r.risk, &r.status, &r.by, &r.version, &r.def)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		return r, r.version > 0
	}
	r, ok := get(on)
	if !ok || r.mode != "live" || r.version != 1 || r.status != "published" || r.by != owner || r.risk != "elevated" {
		t.Fatalf("switched-on automation = %+v", r)
	}
	var def struct {
		Nodes []struct {
			NodeKey string         `json:"node_key"`
			Config  map[string]any `json:"config"`
		} `json:"nodes"`
		Edges []struct {
			Source string `json:"source_node_key"`
			Target string `json:"target_node_key"`
		} `json:"edges"`
	}
	if err := json.Unmarshal(r.def, &def); err != nil || len(def.Nodes) != 2 || len(def.Edges) != 1 || def.Nodes[0].NodeKey != "a" || def.Edges[0].Source != "t" {
		t.Fatalf("definition = %s (%v)", r.def, err)
	}
	if r, ok := get(off); ok || r.mode != "simulate" {
		t.Fatalf("switched-off automation = %+v, want simulate without a version", r)
	}
	if r, _ := get(scan); r.risk != "high" {
		t.Fatalf("scan automation risk = %s, want high", r.risk)
	}
	var runMode string
	if err := db.QueryRow(`SELECT mode FROM automation_runs WHERE id = $1`, run).Scan(&runMode); err != nil || runMode != "live" {
		t.Fatalf("existing run mode = %q (%v), want live", runMode, err)
	}
	// A step may name a node the draft no longer has.
	exec(`INSERT INTO automation_run_steps (automation_run_id, node_id, node_key, node_type) VALUES ($1, gen_random_uuid(), 'gone', 'action')`, run)
	// Two published versions of one automation are refused.
	if _, err := db.Exec(`INSERT INTO automation_versions (tenant_id, automation_id, version, definition, digest, risk_class, status)
		VALUES ($1, $2, 2, '{}', 'x', 'low', 'published')`, tenant, on); err == nil {
		t.Fatal("a second published version was stored")
	}

	// Backfilled rows carry a placeholder until the API stores the canonical
	// digest; after the repair the stored digest equals Definition.Digest().
	var placeholder int
	if err := db.QueryRow(`SELECT count(*) FROM automation_versions WHERE digest = 'backfill'`).Scan(&placeholder); err != nil || placeholder != 2 {
		t.Fatalf("backfill placeholders = %d (%v), want 2", placeholder, err)
	}
	repo := postgres.NewAutomationVersionRepository(&postgres.DB{DB: db})
	if n, err := repo.RepairBackfilledDigests(context.Background()); err != nil || n != 2 {
		t.Fatalf("repair = %d, %v, want 2", n, err)
	}
	if n, err := repo.RepairBackfilledDigests(context.Background()); err != nil || n != 0 {
		t.Fatalf("second repair = %d, %v, want 0 (idempotent)", n, err)
	}
	rows, err := db.Query(`SELECT definition, digest FROM automation_versions WHERE version = 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	checked := 0
	for rows.Next() {
		var raw []byte
		var digest string
		if err := rows.Scan(&raw, &digest); err != nil {
			t.Fatal(err)
		}
		var d automationdom.Definition
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatal(err)
		}
		if digest != d.Digest() || len(digest) != 64 {
			t.Fatalf("stored digest %q != Definition.Digest() %q", digest, d.Digest())
		}
		checked++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if checked != 2 {
		t.Fatalf("checked %d backfilled rows, want 2", checked)
	}

	testdb.Migrate(t, db, dir, v, v, true)
	testdb.Migrate(t, db, dir, v, v, false)

	// The checks added NOT VALID are validated by the next migration.
	vv := testdb.MigrationVersion(t, dir, "automation_versions_validate")
	testdb.Migrate(t, db, dir, vv, vv, false)
	var unvalidated int
	if err := db.QueryRow(`SELECT count(*) FROM pg_constraint WHERE conname IN ('chk_automations_mode', 'chk_automation_runs_mode') AND NOT convalidated`).Scan(&unvalidated); err != nil || unvalidated != 0 {
		t.Fatalf("unvalidated mode checks = %d (%v)", unvalidated, err)
	}
	testdb.Migrate(t, db, dir, vv, vv, true)
	testdb.Migrate(t, db, dir, vv, vv, false)
}
