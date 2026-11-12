package integration

// Migration catalog_report_stubs: global CVE rows a tenant report created lose
// the report's text (archived), become identity stubs, and are filled from the
// corpus when it holds the CVE. Feed-created rows and tenant definitions are
// untouched, and the down migration restores the archived text. Runs on a
// private database: everything up, the migration down, seed, the migration up.

import (
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigrationCatalogReportStubs(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migcatstubs", dir)
	v := testdb.MigrationVersion(t, dir, "catalog_report_stubs")
	testdb.Migrate(t, db, dir, v, v, true)

	const (
		poisoned = "CVE-2099-0101" // reported, the corpus does not know it
		inCorpus = "CVE-2099-0102" // reported, the corpus knows it
		fromFeed = "CVE-2099-0103" // created by the corpus
	)
	if _, err := db.Exec(`
		INSERT INTO vulnerabilities (cve_id, title, description, severity, cvss_score, reference_urls, fixed_versions, origin)
		VALUES ($1, 'crafted title', 'tenant A text', 'low', 0.1, '[{"type":"scanner","url":"https://attacker.example.com"}]', '{9.9.9}', 'report'),
		       ($2, 'crafted title', 'tenant A text', 'low', 0.1, '[]', '{}', 'report'),
		       ($3, 'feed title', 'feed text', 'high', 8.1, '[]', '{}', 'nvd')`, poisoned, inCorpus, fromFeed); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO cve_records (cve_id, description, cvss_score, severity) VALUES ($1, 'corpus text', 9.8, 'critical')`, inCorpus); err != nil {
		t.Fatal(err)
	}

	testdb.Migrate(t, db, dir, v, v, false)

	type row struct {
		title, severity, origin, refs, fixed string
		desc                                 sql.NullString
		cvss                                 sql.NullFloat64
	}
	read := func(cve string) row {
		t.Helper()
		var r row
		if err := db.QueryRow(`SELECT title, severity, origin, reference_urls::text, COALESCE(fixed_versions, '{}')::text, description, cvss_score
			FROM vulnerabilities WHERE cve_id = $1`, cve).Scan(&r.title, &r.severity, &r.origin, &r.refs, &r.fixed, &r.desc, &r.cvss); err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := read(poisoned); r.title != poisoned || r.desc.Valid || r.cvss.Valid || r.severity != "unknown" || r.refs != "[]" || r.fixed != "{}" || r.origin != "report" {
		t.Errorf("reported row not reset to a stub: %+v", r)
	}
	if r := read(inCorpus); r.title != inCorpus || r.desc.String != "corpus text" || r.cvss.Float64 != 9.8 || r.severity != "critical" || r.origin != "nvd" {
		t.Errorf("reported row not filled from the corpus: %+v", r)
	}
	if r := read(fromFeed); r.title != "feed title" || r.desc.String != "feed text" || r.origin != "nvd" {
		t.Errorf("feed row changed: %+v", r)
	}
	var archived int
	if err := db.QueryRow(`SELECT count(*) FROM vulnerability_report_content_archive WHERE description = 'tenant A text'`).Scan(&archived); err != nil || archived != 2 {
		t.Fatalf("archive holds %d reported rows (%v), want 2", archived, err)
	}

	testdb.Migrate(t, db, dir, v, v, true)
	if r := read(poisoned); r.title != "crafted title" || r.desc.String != "tenant A text" || r.origin != "report" || r.fixed != "{9.9.9}" {
		t.Errorf("down did not restore the reported row: %+v", r)
	}
	if r := read(inCorpus); r.desc.String != "tenant A text" || r.origin != "report" {
		t.Errorf("down did not restore the filled row: %+v", r)
	}
	testdb.Migrate(t, db, dir, v, v, false)
	if r := read(poisoned); r.desc.Valid {
		t.Errorf("up again left reported text: %+v", r)
	}
}
