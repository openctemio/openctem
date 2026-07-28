package integration

import (
	"context"
	"database/sql"
	"os"
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
	ctx := context.Background()

	// Ask Postgres directly rather than parsing the constraint text: evaluate
	// the CHECK's own expression against each candidate. Any row shape works —
	// only the source column is under test.
	for _, src := range allSourcesIncludingLegacy() {
		var ok bool
		err := db.QueryRowContext(ctx, `
			SELECT $1::varchar = ANY (ARRAY[
				'sast','dast','sca','secret','iac','container','cspm','easm',
				'rasp','waf','siem','manual','pentest','bug_bounty','red_team',
				'external','threat_intel','vendor','sarif','sca_tool','api'
			]::varchar[])`, string(src)).Scan(&ok)
		if err != nil {
			t.Fatalf("query for %q: %v", src, err)
		}
		if !ok {
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
	ctx := context.Background()

	rows, err := db.QueryContext(ctx, `
		SELECT code FROM finding_sources
		WHERE is_active
		  AND code <> ALL (ARRAY[
			'sast','dast','sca','secret','iac','container','cspm','easm',
			'rasp','waf','siem','manual','pentest','bug_bounty','red_team',
			'external','threat_intel','vendor','sarif','sca_tool','api'
		  ])
		ORDER BY code`)
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
		offenders = append(offenders, code)
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
