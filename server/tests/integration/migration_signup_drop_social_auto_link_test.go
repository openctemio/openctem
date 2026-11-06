package integration

// Migration signup_policy_drop_social_auto_link: a stored social_auto_link is
// dropped from the sign-up policy (the setting no longer exists), the version moves on,
// and the rest of the policy is kept. Runs on a private database: everything
// up to the migration before, seed, up, down, up.

import (
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigrationSignupDropSocialAutoLink(t *testing.T) {
	const dir = "../../migrations"
	v := testdb.MigrationVersion(t, dir, "signup_policy_drop_social_auto_link")
	db := testdb.PrivateDatabase(t, "migdropautolink", dir)
	testdb.Migrate(t, db, dir, v, v, true)

	if _, err := db.Exec(`DELETE FROM platform_settings WHERE key = 'signup_policy'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO platform_settings (key, value, version, source, updated_at)
		VALUES ('signup_policy', '{"mode":"admin_only","accounts":"closed","request_access":true,"social_auto_link":true}', 3, 'console', now())`); err != nil {
		t.Fatal(err)
	}
	check := func(round int, wantVersion int) {
		t.Helper()
		var has, request bool
		var version int
		if err := db.QueryRow(`SELECT value ? 'social_auto_link', (value->>'request_access')::boolean, version
			FROM platform_settings WHERE key = 'signup_policy'`).Scan(&has, &request, &version); err != nil {
			t.Fatal(err)
		}
		if has || !request || version != wantVersion {
			t.Fatalf("round %d: social_auto_link kept=%v request_access=%v version=%d", round, has, request, version)
		}
	}
	testdb.Migrate(t, db, dir, v, v, false)
	check(1, 4)
	testdb.Migrate(t, db, dir, v, v, true)
	testdb.Migrate(t, db, dir, v, v, false)
	check(2, 4) // nothing left to drop: untouched
}
