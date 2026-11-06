package integration

// Migration standard_recon_top_1000: the Standard depth port step of the two
// system recon templates runs the top 1000 ports; Deep is unchanged; a
// tenant's copy (own ids, not a system template) is never touched, edited or
// not; the migration can run again and goes down.
//
// Runs on a private database: everything up, this migration down, seed, up.

import (
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigrationStandardReconTop1000(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migstdtop", dir)
	v := testdb.MigrationVersion(t, dir, "standard_recon_top_1000")
	testdb.Migrate(t, db, dir, v, v, true)

	const (
		stdRecon  = "a0000002-0000-0000-0000-000000000013"
		deepRecon = "a0000002-0000-0000-0000-000000000015"
		tenant    = "a1111111-1111-4111-8111-111111111111"
		copyWf    = "c1111111-1111-4111-8111-111111111111"
		editedWf  = "c2222222-2222-4222-8222-222222222222"
	)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	topN := func(wf, depth string) string {
		t.Helper()
		var s string
		if err := db.QueryRow(`SELECT COALESCE(run_policy #>> ARRAY['depths',$2,'params','top_n'], '') FROM scan_workflow_steps
			WHERE scan_workflow_id = $1 AND step_key = 'ports'`, wf, depth).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}

	// Down state: Standard 100 on both system templates.
	for _, wf := range []string{stdRecon, deepRecon} {
		if got := topN(wf, "standard"); got != "100" {
			t.Fatalf("%s before: standard top_n %q, want 100", wf, got)
		}
	}
	// Tenant copies of the template, one edited by a person (Standard 250).
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'a', 'mig-std-top')`, tenant)
	for i, wf := range []struct{ id, top string }{{copyWf, "100"}, {editedWf, "250"}} {
		exec(`INSERT INTO scan_workflows (id, tenant_id, name, version, triggers, settings, is_active, is_system_template, tags)
			VALUES ($1, $2, $3, 1, '[]', '{}', true, false, '{}')`, wf.id, tenant, "copy"+string(rune('a'+i)))
		exec(`INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, run_policy)
			VALUES (gen_random_uuid(), $1, 'ports', 'Port scan', 1, '{scan.ports}', '{}', 3600, '{}', 'always',
			jsonb_build_object('depths', jsonb_build_object('standard', jsonb_build_object('params', jsonb_build_object('top_n', $2::int)))))`, wf.id, wf.top)
	}

	testdb.Migrate(t, db, dir, v, v, false)
	check := func(phase string) {
		t.Helper()
		for _, wf := range []string{stdRecon, deepRecon} {
			if got := topN(wf, "standard"); got != "1000" {
				t.Errorf("%s %s: system standard top_n %q, want 1000", phase, wf, got)
			}
			if got := topN(wf, "deep"); got != "1000" {
				t.Errorf("%s %s: deep top_n %q, want 1000", phase, wf, got)
			}
		}
		if got := topN(copyWf, "standard"); got != "100" {
			t.Errorf("%s: tenant copy changed to %q", phase, got)
		}
		if got := topN(editedWf, "standard"); got != "250" {
			t.Errorf("%s: edited tenant copy changed to %q", phase, got)
		}
	}
	check("up")
	testdb.Migrate(t, db, dir, v, v, false) // idempotent: the statement matches nothing now
	check("up again")

	testdb.Migrate(t, db, dir, v, v, true)
	for _, wf := range []string{stdRecon, deepRecon} {
		if got := topN(wf, "standard"); got != "100" {
			t.Errorf("down %s: standard top_n %q, want 100", wf, got)
		}
		if got := topN(wf, "deep"); got != "1000" {
			t.Errorf("down %s: deep top_n %q, want 1000", wf, got)
		}
	}
}
