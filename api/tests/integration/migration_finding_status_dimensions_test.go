package integration

// Migration finding_status_dimensions: a finding in validated_fixed or
// not_observed returns to the status it had before (from its timeline, else
// confirmed), keeps the meaning in its dimension and gets a timeline entry;
// stored filter documents are rewritten to the dimension; the status CHECK
// refuses the retired values afterwards; up -> down -> up round-trips.

import (
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

const dimMigTenant = "77777777-7777-4777-8777-777777777777"
const dimMigAsset = "88888888-8888-4888-8888-888888888888"
const dimMigUser = "99999999-9999-4999-8999-999999999999"

func TestMigrationFindingStatusDimensions(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migdims", dir)
	// Three steps: the column, the row moves and filter rewrite, VALIDATE.
	mig := testdb.MigrationVersion(t, dir, "finding_status_dimensions_column")
	validate := testdb.MigrationVersion(t, dir, "finding_status_dimensions_validate")
	testdb.Migrate(t, db, dir, mig, validate, true)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'd', 'mig-dims')`, dimMigTenant)
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($2, $1, 'h', 'host')`, dimMigTenant, dimMigAsset)
	exec(`INSERT INTO users (id, email, name) VALUES ($1, 'dims@mig.test', 'd')`, dimMigUser)

	seed := func(fp, status string) string {
		t.Helper()
		var id string
		if err := db.QueryRow(`INSERT INTO findings (tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, resolution)
			VALUES ($1, $2, 'sca', 't', 'm', 'high', $3, $4, 'branch_expired') RETURNING id::text`,
			dimMigTenant, dimMigAsset, fp, status).Scan(&id); err != nil {
			t.Fatalf("seed %s: %v", fp, err)
		}
		return id
	}
	history := func(id, from, to string) {
		t.Helper()
		exec(`INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, changes)
			VALUES ($1, $2, 'status_changed', 'system', jsonb_build_object('old_status', $3::text, 'new_status', $4::text))`,
			dimMigTenant, id, from, to)
	}
	staleWork := seed("stale-work", "not_observed")
	history(staleWork, "in_progress", "not_observed")
	staleNoHistory := seed("stale-nohist", "not_observed")
	downgraded := seed("downgraded", "validated_fixed")
	history(downgraded, "fix_applied", "validated_fixed")
	untouched := seed("untouched", "new")

	exec(`INSERT INTO saved_views (id, tenant_id, owner_id, page, name, filter) VALUES
		(gen_random_uuid(), $1, $2, 'findings', 'node', '{"v":1,"filter":{"field":"status","op":"in","value":["new","not_observed"]}}'),
		(gen_random_uuid(), $1, $2, 'findings', 'only', '{"v":1,"filter":{"status":["validated_fixed"]}}'),
		(gen_random_uuid(), $1, $2, 'findings', 'not', '{"v":1,"filter":{"field":"status","op":"not_in","value":["not_observed"]}}'),
		(gen_random_uuid(), $1, $2, 'findings', 'plain', '{"v":1,"filter":{"status":["new"]}}')`, dimMigTenant, dimMigUser)

	testdb.Migrate(t, db, dir, mig, validate, false)

	type row struct{ status, observation, validation, resolution string }
	read := func(id string) row {
		t.Helper()
		var r row
		var v, res sql.NullString
		if err := db.QueryRow(`SELECT status, observation_state, validation_outcome, resolution FROM findings WHERE id = $1`, id).
			Scan(&r.status, &r.observation, &v, &res); err != nil {
			t.Fatal(err)
		}
		r.validation, r.resolution = v.String, res.String
		return r
	}
	for name, c := range map[string]struct {
		id   string
		want row
	}{
		"stale, back to its work state":   {staleWork, row{"in_progress", "stale", "", ""}},
		"stale, no history: confirmed":    {staleNoHistory, row{"confirmed", "stale", "", ""}},
		"downgraded, back to fix_applied": {downgraded, row{"fix_applied", "present", "not_reproducible", ""}},
		"other statuses untouched":        {untouched, row{"new", "present", "", "branch_expired"}},
	} {
		if got := read(c.id); got != c.want {
			t.Errorf("%s: %+v, want %+v", name, got, c.want)
		}
	}
	// Each moved finding has a timeline entry from the migration.
	var entries int
	if err := db.QueryRow(`SELECT COUNT(*) FROM finding_activities WHERE source = 'migration' AND changes->>'reason' = 'status_retired'`).
		Scan(&entries); err != nil || entries != 3 {
		t.Errorf("migration timeline entries = %d (%v), want 3", entries, err)
	}
	// The retired values are refused now.
	if _, err := db.Exec(`UPDATE findings SET status = 'not_observed' WHERE id = $1`, untouched); err == nil {
		t.Error("not_observed is still accepted as a status")
	}

	views := savedViewFilters(t, db, dimMigTenant)
	wantViews := map[string]string{
		"node":  `{"v": 1, "filter": {"any": [{"op": "in", "field": "status", "value": ["new"]}, {"op": "eq", "field": "observation", "value": "stale"}]}}`,
		"only":  `{"v": 1, "filter": {"validation": "not_reproducible"}}`,
		"not":   `{"v": 1, "filter": {"op": "in", "field": "observation", "value": ["present", "stale"]}}`,
		"plain": `{"v": 1, "filter": {"status": ["new"]}}`,
	}
	for n, want := range wantViews {
		if !sameJSON(t, views[n], want) {
			t.Errorf("view %s = %s, want %s", n, views[n], want)
		}
	}

	// Down then up again: the statuses come back as allowed, the dimension
	// column goes and returns.
	testdb.Migrate(t, db, dir, mig, validate, true)
	exec(`UPDATE findings SET status = 'not_observed' WHERE id = $1`, untouched)
	exec(`UPDATE findings SET status = 'new' WHERE id = $1`, untouched)
	testdb.Migrate(t, db, dir, mig, validate, false)
	if got := read(untouched); got.status != "new" || got.observation != "present" {
		t.Errorf("after up again: %+v", got)
	}
}

func sameJSON(t *testing.T, a, b string) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal([]byte(a), &x); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(b), &y); err != nil {
		t.Fatal(err)
	}
	xa, _ := json.Marshal(x)
	ya, _ := json.Marshal(y)
	return string(xa) == string(ya)
}

func savedViewFilters(t *testing.T, db *sql.DB, tenant string) map[string]string {
	t.Helper()
	rows, err := db.Query(`SELECT name, filter::text FROM saved_views WHERE tenant_id = $1`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	views := map[string]string{}
	for rows.Next() {
		var n, f string
		if err := rows.Scan(&n, &f); err != nil {
			t.Fatal(err)
		}
		views[n] = f
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return views
}
