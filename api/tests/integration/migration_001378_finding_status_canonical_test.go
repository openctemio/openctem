package integration

// Migration 001378: one finding status set. Rows in a retired pentest alias
// (or the never-valid "open") map to the canonical status, a verified finding
// keeps that it was verified by a retest as its resolution method, the CHECK
// then refuses the aliases, and running the migration again changes nothing.
// Runs on a private database: everything up, 001561 and 001378 down, seed,
// 001378 up.

import (
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigration001378FoldsStatusAliases(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "mig1378", dir)
	// 001561 dropped pentest_findings; its down recreates the table 001378
	// works on.
	testdb.Migrate(t, db, dir, 1555, 1555, true)
	testdb.Migrate(t, db, dir, 1378, 1378, true)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const tenant = "11111111-1111-4111-8111-111111111111"
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'm', 'mig-1378')`, tenant)
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ('22222222-2222-4222-8222-222222222222', $1, 'h', 'host')`, tenant)
	exec(`INSERT INTO findings (tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		SELECT $1, '22222222-2222-4222-8222-222222222222', 'pentest', 'manual', 'm', 'high', 'fp-' || s, s
		FROM unnest(ARRAY['remediation','retest','verified','accepted_risk','open','new','resolved','draft']) s`, tenant)
	exec(`INSERT INTO pentest_campaigns (id, tenant_id, name) VALUES ('33333333-3333-4333-8333-333333333333', $1, 'c')`, tenant)
	exec(`INSERT INTO pentest_findings (tenant_id, campaign_id, title, status)
		SELECT $1, '33333333-3333-4333-8333-333333333333', 't-' || s, s
		FROM unnest(ARRAY['remediation','retest','verified','accepted_risk','confirmed']) s`, tenant)

	want := map[string]string{
		"remediation": "in_progress", "retest": "fix_applied", "verified": "resolved",
		"accepted_risk": "accepted", "open": "new", "new": "new", "resolved": "resolved", "draft": "draft",
	}
	pentestWant := map[string]string{
		"remediation": "in_progress", "retest": "fix_applied", "verified": "resolved",
		"accepted_risk": "accepted", "confirmed": "confirmed",
	}
	check := func(round string) {
		t.Helper()
		for from, to := range want {
			var got string
			if err := db.QueryRow(`SELECT status FROM findings WHERE fingerprint = $1`, "fp-"+from).Scan(&got); err != nil || got != to {
				t.Errorf("%s: finding in %s -> %s (%v), want %s", round, from, got, err, to)
			}
		}
		for from, to := range pentestWant {
			var got string
			if err := db.QueryRow(`SELECT status FROM pentest_findings WHERE title = $1`, "t-"+from).Scan(&got); err != nil || got != to {
				t.Errorf("%s: pentest finding in %s -> %s (%v), want %s", round, from, got, err, to)
			}
		}
		var method string
		var regression bool
		if err := db.QueryRow(`SELECT COALESCE(resolution_method, ''), is_regression FROM findings WHERE fingerprint = 'fp-verified'`).
			Scan(&method, &regression); err != nil || method != "retest_verified" || regression {
			t.Errorf("%s: verified finding method %q regression %v (%v)", round, method, regression, err)
		}
	}

	testdb.Migrate(t, db, dir, 1378, 1378, false)
	check("up")
	// Down then up again changes nothing.
	testdb.Migrate(t, db, dir, 1378, 1378, true)
	testdb.Migrate(t, db, dir, 1378, 1378, false)
	check("down-up")

	for _, alias := range []string{"verified", "accepted_risk", "remediation", "retest", "open"} {
		if _, err := db.Exec(`UPDATE findings SET status = $1 WHERE fingerprint = 'fp-new'`, alias); err == nil {
			t.Errorf("findings CHECK accepts %s", alias)
		}
		if _, err := db.Exec(`UPDATE pentest_findings SET status = $1 WHERE title = 't-confirmed'`, alias); err == nil {
			t.Errorf("pentest_findings CHECK accepts %s", alias)
		}
	}
}
