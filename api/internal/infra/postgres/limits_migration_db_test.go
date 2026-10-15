package postgres

import (
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The migration that replaces plans with per-organization limits keeps every
// organization's caps exactly: a Free organization gets the Free limits as
// operator limits (an existing override wins), modules its plan left out
// become denies (unless granted), organizations without a plan or on Pro get
// nothing, the per-person Free cap is dropped, and plans are gone.
func TestLimitsReplacePlansMigration_DB(t *testing.T) {
	dir := "../../../migrations"
	db := testdb.PrivateDatabase(t, "limits_replace_plans", dir)
	v := testdb.MigrationVersion(t, dir, "limits_replace_plans")
	testdb.Migrate(t, db, dir, v, v, true) // back to plans

	free, overridden, pro, none := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	for _, id := range []shared.ID{free, overridden, pro, none} {
		if _, err := db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, id.String(), "lim-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenant_plans (tenant_id, plan) VALUES ($1, 'free'), ($2, 'free'), ($3, 'pro')`, []any{free.String(), overridden.String(), pro.String()}},
		{`INSERT INTO tenant_plan_overrides (tenant_id, limit_key, value, reason) VALUES ($1, 'seats', 50, 'sales'), ($1, 'free_teams_per_user', 3, 'x')`, []any{overridden.String()}},
		{`INSERT INTO platform_settings (key, value) VALUES ('plan_modules', '{"free":["pentest"],"pro":["*"],"enterprise":["*"]}')`, nil},
		{`INSERT INTO tenant_module_grants (tenant_id, module_id, kind, reason) VALUES ($1, 'reports', 'grant', 'trial'), ($2, 'iocs', 'deny', 'contract')`, []any{free.String(), pro.String()}},
	} {
		if _, err := db.Exec(q.sql, q.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	testdb.Migrate(t, db, dir, v, v, false)

	limit := func(id shared.ID, key string) int {
		t.Helper()
		var v int
		err := db.QueryRow(`SELECT value FROM tenant_limits WHERE tenant_id = $1 AND limit_key = $2 AND origin = 'operator'`, id.String(), key).Scan(&v)
		if err != nil {
			return -2
		}
		return v
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := db.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	if limit(free, "seats") != 5 || limit(free, "assets") != 500 || limit(free, "platform_scans_concurrent") != 1 {
		t.Fatalf("Free organization keeps the Free limits: seats=%d assets=%d", limit(free, "seats"), limit(free, "assets"))
	}
	if limit(overridden, "seats") != 50 || limit(overridden, "sensors") != 2 {
		t.Fatalf("an override wins over the plan value: seats=%d sensors=%d", limit(overridden, "seats"), limit(overridden, "sensors"))
	}
	if n := count(`SELECT count(*) FROM tenant_limits WHERE limit_key = 'free_teams_per_user'`); n != 0 {
		t.Fatalf("free_teams_per_user rows must go: %d", n)
	}
	if n := count(`SELECT count(*) FROM tenant_limits WHERE tenant_id = ANY($1)`, []string{pro.String(), none.String()}); n != 0 {
		t.Fatalf("Pro and unassigned organizations had no limits: %d rows", n)
	}

	denied := func(id shared.ID, feature string) bool {
		return count(`SELECT count(*) FROM tenant_feature_denies WHERE tenant_id = $1 AND feature = $2`, id.String(), feature) == 1
	}
	if denied(free, "pentest") || denied(free, "reports") || !denied(free, "attack_surface") {
		t.Fatal("Free: in-plan and granted modules stay available; the rest are denied")
	}
	if !denied(pro, "iocs") || count(`SELECT count(*) FROM tenant_feature_denies WHERE tenant_id = $1`, pro.String()) != 1 {
		t.Fatal("Pro keeps its explicit deny only")
	}
	if count(`SELECT count(*) FROM tenant_feature_denies WHERE tenant_id = $1`, none.String()) != 0 {
		t.Fatal("an organization without a plan gets no denies")
	}
	if count(`SELECT count(*) FROM tenant_feature_denies WHERE tenant_id = $1 AND feature = 'iocs' AND origin = 'operator'`, pro.String()) != 1 {
		t.Fatal("migrated rows are operator rows")
	}
	if count(`SELECT count(*) FROM information_schema.tables WHERE table_name = 'tenant_plans'`) != 0 ||
		count(`SELECT count(*) FROM platform_settings WHERE key IN ('plan_limits', 'plan_modules')`) != 0 {
		t.Fatal("plans and plan settings must be gone")
	}

	// Reversible: down restores the shape (plans are not recoverable), up again.
	testdb.Migrate(t, db, dir, v, v, true)
	testdb.Migrate(t, db, dir, v, v, false)
	if limit(free, "seats") != 5 {
		t.Fatal("operator limits survive down and up")
	}
}
