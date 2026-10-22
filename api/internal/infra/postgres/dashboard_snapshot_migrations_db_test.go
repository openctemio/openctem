package postgres

import (
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Migration dashboard_facts_pentest_no_campaign stores pentest findings
// without a campaign under the all-f campaign id and asks for a full
// rebuild of every tenant whose facts are built; down restores the
// all-zero id. Migration dashboard_snapshots_member_removal deletes a
// member's personal snapshots when the membership is deleted or stops being
// active, and only theirs.
func TestDashboardSnapshotMigrations_DB(t *testing.T) {
	dir := "../../../migrations"
	db := testdb.PrivateDatabase(t, "dash_snap_hardening", dir)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	tenant, other, asset := shared.NewID(), shared.NewID(), shared.NewID()
	for _, tid := range []shared.ID{tenant, other} {
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tid.String(), "t-"+tid.String())
	}
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'a', 'domain')`, asset.String(), tenant.String())
	exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, title, severity, fingerprint, status, priority_class)
		VALUES ($1::uuid, $2, $3, 'pentest', 'pt', 'no campaign', 'no campaign', 'high', $1::text, 'confirmed', 'P1')`,
		shared.NewID().String(), tenant.String(), asset.String())
	campaignOf := func() string {
		t.Helper()
		var c string
		if _, err := db.Exec(`SELECT dash_recompute_asset($1, $2)`, tenant.String(), asset.String()); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT pentest_campaign_id::text FROM dash_asset_day WHERE tenant_id = $1 AND asset_id = $2`,
			tenant.String(), asset.String()).Scan(&c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	if c := campaignOf(); c != "ffffffff-ffff-ffff-ffff-ffffffffffff" {
		t.Errorf("pentest finding without a campaign stored under %s, want the all-f id", c)
	}
	var state string
	if err := db.QueryRow(`SELECT pentest_campaign_id::text FROM dash_asset_state WHERE tenant_id = $1 AND asset_id = $2`,
		tenant.String(), asset.String()).Scan(&state); err != nil || state != "ffffffff-ffff-ffff-ffff-ffffffffffff" {
		t.Errorf("F1 campaign = %q (%v)", state, err)
	}

	v := testdb.MigrationVersion(t, dir, "dashboard_facts_pentest_no_campaign")
	testdb.Migrate(t, db, dir, v, v, true)
	if c := campaignOf(); c != "00000000-0000-0000-0000-000000000000" {
		t.Errorf("after down: stored under %s, want the all-zero id", c)
	}
	exec(`INSERT INTO dash_fact_status (tenant_id, rebuilt_at) VALUES ($1, now())`, tenant.String())
	exec(`INSERT INTO dash_fact_status (tenant_id) VALUES ($1)`, other.String())
	exec(`UPDATE dash_fact_status SET rebuild_requested_at = NULL`)
	testdb.Migrate(t, db, dir, v, v, false)
	var built, unbuilt bool
	_ = db.QueryRow(`SELECT rebuild_requested_at IS NOT NULL FROM dash_fact_status WHERE tenant_id = $1`, tenant.String()).Scan(&built)
	_ = db.QueryRow(`SELECT rebuild_requested_at IS NOT NULL FROM dash_fact_status WHERE tenant_id = $1`, other.String()).Scan(&unbuilt)
	if !built || unbuilt {
		t.Errorf("rebuild requested: built tenant %v (want true), unbuilt tenant %v (want false: its first build is pending)", built, unbuilt)
	}

	// Member removal.
	users := map[string]shared.ID{}
	for _, n := range []string{"gone", "suspended", "stays", "elsewhere"} {
		users[n] = shared.NewID()
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, $3)`, users[n].String(), n+"-"+users[n].String()+"@example.test", n)
	}
	snap := func(tid, uid shared.ID) {
		t.Helper()
		d := shared.NewID()
		exec(`INSERT INTO tenant_members (tenant_id, user_id, role) VALUES ($1, $2, 'member') ON CONFLICT DO NOTHING`, tid.String(), uid.String())
		exec(`INSERT INTO user_dashboards (id, tenant_id, user_id, name, kind) VALUES ($1, $2, $3, 'd', 'personal')`, d.String(), tid.String(), uid.String())
		exec(`INSERT INTO dash_snapshots (tenant_id, dashboard_id, kind, owner_user_id, scope_key, layout_hash, data, computed_at)
			VALUES ($1, $2, 'personal', $3, 'k', 'h', '{}', now())`, tid.String(), d.String(), uid.String())
	}
	snap(tenant, users["gone"])
	snap(tenant, users["suspended"])
	snap(tenant, users["stays"])
	snap(tenant, users["elsewhere"])
	snap(other, users["elsewhere"])
	exec(`DELETE FROM tenant_members WHERE tenant_id = $1 AND user_id = $2`, tenant.String(), users["gone"].String())
	exec(`UPDATE tenant_members SET status = 'suspended' WHERE tenant_id = $1 AND user_id = $2`, tenant.String(), users["suspended"].String())
	exec(`DELETE FROM tenant_members WHERE tenant_id = $1 AND user_id = $2`, other.String(), users["elsewhere"].String())
	count := func(tid, uid shared.ID) int {
		var n int
		_ = db.QueryRow(`SELECT count(*) FROM dash_snapshots WHERE tenant_id = $1 AND owner_user_id = $2`, tid.String(), uid.String()).Scan(&n)
		return n
	}
	for _, tc := range []struct {
		name string
		tid  shared.ID
		uid  shared.ID
		want int
	}{
		{"removed member", tenant, users["gone"], 0},
		{"suspended member", tenant, users["suspended"], 0},
		{"active member", tenant, users["stays"], 1},
		{"removed from another organization only", tenant, users["elsewhere"], 1},
		{"removed there", other, users["elsewhere"], 0},
	} {
		if got := count(tc.tid, tc.uid); got != tc.want {
			t.Errorf("%s: snapshots = %d, want %d", tc.name, got, tc.want)
		}
	}
	mv := testdb.MigrationVersion(t, dir, "dashboard_snapshots_member_removal")
	testdb.Migrate(t, db, dir, mv, mv, true)
	testdb.Migrate(t, db, dir, mv, mv, false)
}
