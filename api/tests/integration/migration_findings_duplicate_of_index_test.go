package integration

// Migration findings_duplicate_of_index: the self-reference findings.duplicate_of
// is indexed, so the ON DELETE SET NULL action of a deleted finding looks up
// its duplicates through the index instead of scanning the table. Up, down
// and up again.

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigrationFindingsDuplicateOfIndex(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migdupof", dir)
	v := testdb.MigrationVersion(t, dir, "findings_duplicate_of_index")

	valid := func() (exists, ok bool) {
		t.Helper()
		var isValid bool
		err := db.QueryRow(`SELECT i.indisvalid FROM pg_index i
			JOIN pg_class c ON c.oid = i.indexrelid
			WHERE c.relname = 'idx_findings_duplicate_of'`).Scan(&isValid)
		if err != nil {
			return false, false
		}
		return true, isValid
	}
	if exists, ok := valid(); !exists || !ok {
		t.Fatalf("after up: index exists=%v valid=%v", exists, ok)
	}

	// The lookup the foreign key action runs uses the index.
	if _, err := db.Exec(`SET enable_seqscan = off`); err != nil {
		t.Fatal(err)
	}
	var plan strings.Builder
	rows, err := db.Query(`EXPLAIN SELECT 1 FROM findings WHERE duplicate_of = '00000000-0000-0000-0000-000000000001'`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(line + "\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	_ = rows.Close()
	if !strings.Contains(plan.String(), "idx_findings_duplicate_of") {
		t.Fatalf("duplicate_of lookup does not use the index:\n%s", plan.String())
	}

	testdb.Migrate(t, db, dir, v, v, true)
	if exists, _ := valid(); exists {
		t.Fatal("after down: index still exists")
	}
	testdb.Migrate(t, db, dir, v, v, false)
	if exists, ok := valid(); !exists || !ok {
		t.Fatalf("after up again: index exists=%v valid=%v", exists, ok)
	}
}
