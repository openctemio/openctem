package integration

// Migration finding_severity_override: rolling it back restores the
// finding_activities.chk_activity_type constraint validated, not NOT VALID.
// Up, down, up again.

import (
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigrationFindingSeverityOverrideDownValidatesActivityType(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migsevovr", dir)
	v := testdb.MigrationVersion(t, dir, "finding_severity_override")

	validated := func() bool {
		t.Helper()
		var ok bool
		err := db.QueryRow(`SELECT convalidated FROM pg_constraint
			WHERE conname = 'chk_activity_type' AND conrelid = 'finding_activities'::regclass`).Scan(&ok)
		if err == sql.ErrNoRows {
			t.Fatal("chk_activity_type does not exist")
		}
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !validated() {
		t.Fatal("after up: chk_activity_type is not validated")
	}

	testdb.Migrate(t, db, dir, v, v, true)
	if !validated() {
		t.Fatal("after down: chk_activity_type was re-added NOT VALID")
	}
	// The up adds the constraint NOT VALID (no scan under the lock) and the
	// next migration validates it; up again must still apply cleanly.
	testdb.Migrate(t, db, dir, v, v, false)
}
