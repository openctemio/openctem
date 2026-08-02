package integration

import (
	"context"
	"database/sql"
	"os"
	"regexp"
	"sort"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// There are three definitions of "valid finding source" — the Go consts, the
// CHECK constraint on findings.source, and the finding_sources catalog — and
// value_objects.go documents a three-step procedure for keeping them together.
// Step 1 ("add a migration to insert the new source into finding_sources") was
// skipped for eleven of twenty sources, and nothing noticed, because nothing
// checked. These tests are that check.
//
// They cost one query each. The drift they guard against shipped a dropdown
// option the database rejects.

// checkConstraintValues reads the values the findings.source CHECK actually
// accepts, straight from the catalog. An earlier version of this file restated
// the list inline — which created a fourth definition of the thing these tests
// exist to keep singular, and went stale the moment 'va' was added. Read the
// truth; do not copy it.
func checkConstraintValues(t *testing.T, db *sql.DB) map[string]bool {
	t.Helper()

	// Count first. LIMIT 1 was not enough: a migration that drops the wrong
	// constraint name leaves the original in place and adds a second one, and a
	// row then has to satisfy both. That is exactly how migration 000196 first
	// failed, and reading only one of the two constraints would have let it
	// through — a test that cannot catch the bug it was written for.
	var constraintCount int
	if err := db.QueryRow(`
		SELECT count(*) FROM pg_constraint
		WHERE conrelid = 'findings'::regclass
		  AND contype = 'c'
		  AND pg_get_constraintdef(oid) LIKE '%source%'`).Scan(&constraintCount); err != nil {
		t.Fatalf("count findings.source CHECK constraints: %v", err)
	}
	if constraintCount != 1 {
		t.Fatalf("expected exactly 1 CHECK constraint on findings.source, found %d. "+
			"A row must satisfy all of them, so a second one silently narrows what can be stored.",
			constraintCount)
	}

	var def string
	err := db.QueryRow(`
		SELECT pg_get_constraintdef(oid)
		FROM pg_constraint
		WHERE conrelid = 'findings'::regclass
		  AND contype = 'c'
		  AND pg_get_constraintdef(oid) LIKE '%source%'`).Scan(&def)
	if err != nil {
		t.Fatalf("read findings.source CHECK constraint: %v", err)
	}

	// pg_get_constraintdef renders the IN list as quoted literals; every legal
	// source code is lowercase letters and underscores.
	re := regexp.MustCompile(`'([a-z_]+)'`)
	values := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(def, -1) {
		values[m[1]] = true
	}
	if len(values) == 0 {
		t.Fatalf("parsed no values out of the CHECK constraint: %s", def)
	}
	return values
}

func openParityDB(t *testing.T) *sql.DB {
	t.Helper()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping finding-source parity check")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("cannot open DATABASE_URL: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return db
}

// Every source the application can construct must be storable. This is the
// direction that matters most: if it fails, a code path produces findings the
// database refuses, and the failure surfaces as a 500 at insert time.
func TestFindingSource_EveryGoConstantPassesTheCheckConstraint(t *testing.T) {
	db := openParityDB(t)
	allowed := checkConstraintValues(t, db)

	for _, src := range allSourcesIncludingLegacy() {
		if !allowed[string(src)] {
			t.Errorf("Go constant %q is not accepted by the findings.source CHECK constraint. "+
				"Any code path producing it will fail at insert. Add it to the CHECK in a migration.", src)
		}
	}
}

// Every storable source must be displayable. A finding whose source has no
// catalog row cannot be labeled, colored or grouped in the UI — which is
// how easm and cspm findings ended up as bare lowercase text.
func TestFindingSource_EveryGoConstantHasACatalogRow(t *testing.T) {
	db := openParityDB(t)
	ctx := context.Background()

	rows, err := db.QueryContext(ctx, `SELECT code FROM finding_sources WHERE is_active`)
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	defer func() { _ = rows.Close() }()

	catalog := map[string]bool{}
	for rows.Next() {
		var code string
		if err := rows.Scan(&code); err != nil {
			t.Fatalf("scan: %v", err)
		}
		catalog[code] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}

	var missing []string
	for _, src := range allSourcesIncludingLegacy() {
		if !catalog[string(src)] {
			missing = append(missing, string(src))
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("finding_sources has no active row for %v. "+
			"value_objects.go documents the procedure: add the migration first, then the constant.", missing)
	}
}

// The catalog must not advertise what cannot be stored. 'import' was seeded,
// shown in the Add Finding dialog, and rejected by the CHECK — a user could
// pick an option that always failed.
func TestFindingSource_CatalogOffersNothingUnstorable(t *testing.T) {
	db := openParityDB(t)
	allowed := checkConstraintValues(t, db)

	rows, err := db.Query(`SELECT code FROM finding_sources WHERE is_active ORDER BY code`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var offenders []string
	for rows.Next() {
		var code string
		if err := rows.Scan(&code); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if !allowed[code] {
			offenders = append(offenders, code)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}

	if len(offenders) > 0 {
		t.Errorf("finding_sources offers %v, which the findings.source CHECK constraint rejects. "+
			"Selecting one in the UI fails the insert.", offenders)
	}
}

// Every catalog row must belong to a category, or the grouped source picker
// silently drops it.
func TestFindingSource_EveryCatalogRowHasACategory(t *testing.T) {
	db := openParityDB(t)

	var orphans int
	err := db.QueryRow(`SELECT count(*) FROM finding_sources WHERE is_active AND category_id IS NULL`).Scan(&orphans)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if orphans > 0 {
		t.Errorf("%d active finding_sources rows have no category_id; groupFindingSourcesByCategory drops them", orphans)
	}
}

func allSourcesIncludingLegacy() []vulnerability.FindingSource {
	out := vulnerability.AllFindingSources()
	// AllFindingSources is documented as "primary only, excluding legacy", but
	// legacy values are still storable and still need a label.
	return append(out, vulnerability.FindingSourceSARIF, vulnerability.FindingSourceSCATool)
}
