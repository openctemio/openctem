package postgres

import (
	"context"
	"testing"
)

// A fully migrated schema has no pre-rename leftovers on any supported
// PostgreSQL version. PostgreSQL 18 records each column's NOT NULL as a
// pg_constraint row named <table>_<column>_not_null, so a NOT NULL user_agent
// column must not count as a constraint "still named *agent*".
func TestCheckSensorRename_MigratedSchemaHasNoLeftovers(t *testing.T) {
	db := openGroupsDB(t)
	items, err := CheckSensorRename(context.Background(), db, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if it.Area == "schema" && it.Leftover() {
			t.Errorf("schema leftover on a migrated database: %s (count %d)", it.What, it.Count)
		}
	}
}
