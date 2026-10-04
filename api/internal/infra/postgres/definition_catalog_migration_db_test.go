package postgres

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
)

// Migrations 000820-000827 (RFC-044 P1): the CVE catalog becomes the
// definition catalog in place. This replays them on a populated private
// database, up -> down -> up, and checks the backfill and that the down
// migrations restore the old schema without losing a catalog row or a
// finding's catalog link.
// https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-044-issue-definitions-and-findings.md

const (
	defCatalogFirst = 820
	defCatalogLast  = 827
	// More findings than four backfill batches (1000 each), so the batching is crossed.
	defCatalogFindings = 4100
)

var defCatalogPast = time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)

type defCatalogSeed struct {
	tenantA, tenantB string
	kevVuln          string // in CISA KEV, CVSS 3.1 vector, nickname + identifier-shaped alias
	v2Vuln           string // bare CVSS v2 vector
	plainVuln        string // no vector, never linked
	linked           int    // findings with a catalog link
}

func TestDefinitionCatalogMigrations_UpDownUp(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "migrations")
	db := testdb.PrivateDatabaseThrough(t, "rfc044p1", dir, defCatalogFirst-1)
	ctx := context.Background()

	seed := seedDefinitionCatalogOldSchema(ctx, t, db)

	testdb.Migrate(t, db, dir, defCatalogFirst, defCatalogLast, false)
	assertDefinitionCatalogBackfill(ctx, t, db, seed)

	testdb.Migrate(t, db, dir, defCatalogFirst, defCatalogLast, true)
	assertDefinitionCatalogReverted(ctx, t, db, seed)

	testdb.Migrate(t, db, dir, defCatalogFirst, defCatalogLast, false)
	assertDefinitionCatalogBackfill(ctx, t, db, seed)
}

func seedDefinitionCatalogOldSchema(ctx context.Context, t *testing.T, db *sql.DB) defCatalogSeed {
	t.Helper()
	var s defCatalogSeed
	mustQueryRow(ctx, t, db, `INSERT INTO tenants (name, slug) VALUES ('A', 'rfc044-a') RETURNING id`).Scan(&s.tenantA)
	mustQueryRow(ctx, t, db, `INSERT INTO tenants (name, slug) VALUES ('B', 'rfc044-b') RETURNING id`).Scan(&s.tenantB)

	insertVuln := func(cve, vector string, aliases []string) string {
		var id string
		mustQueryRow(ctx, t, db, `
			INSERT INTO vulnerabilities (cve_id, title, severity, cvss_vector, aliases, created_at, updated_at)
			VALUES ($1, 'title', 'high', NULLIF($2, ''), $3, $4, $4) RETURNING id`,
			cve, vector, pq.Array(aliases), defCatalogPast).Scan(&id)
		return id
	}
	s.kevVuln = insertVuln("CVE-2021-44228", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		[]string{"Log4Shell", "GHSA-jfh8-c2jp-5v3q", " ", "Log4Shell"})
	s.v2Vuln = insertVuln("CVE-2014-0160", "AV:N/AC:L/Au:N/C:P/I:N/A:N", nil)
	s.plainVuln = insertVuln("CVE-2099-0001", "", nil)
	mustExec(t, db, `INSERT INTO kev_catalog (cve_id, vulnerability_name, date_added) VALUES ('CVE-2021-44228', 'Log4j', '2021-12-10')`)

	// Two assets per tenant; every third finding is linked, alternating the
	// two linked CVEs.
	mustExec(t, db, `
		INSERT INTO assets (tenant_id, name, asset_type)
		SELECT t.id, 'host-' || t.slug || '-' || g, 'host'
		FROM tenants t CROSS JOIN generate_series(1, 2) g
		WHERE t.slug IN ('rfc044-a', 'rfc044-b')`)
	mustExec(t, db, `
		WITH a AS (SELECT id, tenant_id, row_number() OVER (ORDER BY id) - 1 AS rn
		           FROM assets WHERE name LIKE 'host-rfc044-%')
		INSERT INTO findings (tenant_id, asset_id, source, tool_name, message, severity, status,
		                      fingerprint, vulnerability_id, cve_id, updated_at)
		SELECT a.tenant_id, a.id, 'sca', 'trivy', 'm', 'high', 'new', 'rfc044-fp-' || g,
		       CASE WHEN g % 3 = 0 THEN CASE WHEN g % 2 = 0 THEN $1::uuid ELSE $2::uuid END END,
		       CASE WHEN g % 3 = 0 THEN CASE WHEN g % 2 = 0 THEN 'CVE-2021-44228' ELSE 'CVE-2014-0160' END END,
		       $3
		FROM generate_series(1, $4::int) g
		JOIN a ON a.rn = g % 4`, s.kevVuln, s.v2Vuln, defCatalogPast, defCatalogFindings)
	mustQueryRow(ctx, t, db, `SELECT count(*) FROM findings WHERE vulnerability_id IS NOT NULL`).Scan(&s.linked)
	if s.linked == 0 {
		t.Fatal("seed: no linked findings")
	}
	return s
}

func assertDefinitionCatalogBackfill(ctx context.Context, t *testing.T, db *sql.DB, s defCatalogSeed) {
	t.Helper()

	type defRow struct {
		namespace, externalID, kind, lifecycle, origin, scope string
		cvssVersion                                           sql.NullString
		nicknames                                             []string
		tenant                                                sql.NullString
		updatedAt                                             time.Time
	}
	read := func(id string) defRow {
		var r defRow
		mustQueryRow(ctx, t, db, `
			SELECT namespace, external_id, kind, lifecycle, origin, scope_tenant_id, cvss_version,
			       nicknames, tenant_id, updated_at
			FROM vulnerabilities WHERE id = $1`, id).Scan(&r.namespace, &r.externalID, &r.kind,
			&r.lifecycle, &r.origin, &r.scope, &r.cvssVersion, pq.Array(&r.nicknames), &r.tenant, &r.updatedAt)
		return r
	}
	for _, c := range []struct {
		id, cve, origin, cvssVersion string
		nicknames                    []string
	}{
		{s.kevVuln, "CVE-2021-44228", "kev", "3.1", []string{"Log4Shell"}},
		{s.v2Vuln, "CVE-2014-0160", "report", "2.0", nil},
		{s.plainVuln, "CVE-2099-0001", "report", "", nil},
	} {
		r := read(c.id)
		if r.namespace != "CVE" || r.externalID != c.cve || r.kind != "vulnerability" || r.lifecycle != "published" {
			t.Errorf("%s: identity %s/%s kind %s lifecycle %s", c.cve, r.namespace, r.externalID, r.kind, r.lifecycle)
		}
		if r.tenant.Valid || r.scope != "00000000-0000-0000-0000-000000000000" {
			t.Errorf("%s: scope tenant=%v scope=%s, want global", c.cve, r.tenant, r.scope)
		}
		if r.origin != c.origin {
			t.Errorf("%s: origin %s, want %s", c.cve, r.origin, c.origin)
		}
		if r.cvssVersion.String != c.cvssVersion {
			t.Errorf("%s: cvss_version %q, want %q", c.cve, r.cvssVersion.String, c.cvssVersion)
		}
		if len(r.nicknames) != len(c.nicknames) || (len(c.nicknames) > 0 && r.nicknames[0] != c.nicknames[0]) {
			t.Errorf("%s: nicknames %v, want %v", c.cve, r.nicknames, c.nicknames)
		}
		if !r.updatedAt.Equal(defCatalogPast) {
			t.Errorf("%s: updated_at moved to %s by the backfill", c.cve, r.updatedAt)
		}
	}

	// One primary identifier per definition, asserted by its origin. The
	// identifier-shaped alias a report wrote is not promoted to a global alias.
	var defs, primaries, mismatched, ghsa int
	mustQueryRow(ctx, t, db, `
		SELECT (SELECT count(*) FROM vulnerabilities),
		       count(*) FILTER (WHERE di.is_primary),
		       count(*) FILTER (WHERE di.namespace <> v.namespace OR di.external_id <> v.external_id
		                         OR di.asserted_by <> v.origin OR di.scope_tenant_id <> v.scope_tenant_id),
		       count(*) FILTER (WHERE di.namespace = 'GHSA')
		FROM definition_identifiers di JOIN vulnerabilities v ON v.id = di.definition_id`).
		Scan(&defs, &primaries, &mismatched, &ghsa)
	if primaries != defs || mismatched != 0 || ghsa != 0 {
		t.Errorf("identifiers: %d primaries for %d definitions, %d mismatched, %d GHSA", primaries, defs, mismatched, ghsa)
	}

	// Every linked finding has its catalog entry as its primary definition,
	// in its own tenant; nothing else got a link; updated_at untouched.
	var links, primaryLinks, wrongTenant, defSet, defMismatch, touched int
	mustQueryRow(ctx, t, db, `
		SELECT (SELECT count(*) FROM finding_definitions),
		       (SELECT count(*) FROM finding_definitions fd JOIN findings f ON f.id = fd.finding_id
		         WHERE fd.ord = 0 AND fd.role = 'primary' AND fd.definition_id = f.vulnerability_id),
		       (SELECT count(*) FROM finding_definitions fd JOIN findings f ON f.id = fd.finding_id
		         WHERE fd.tenant_id <> f.tenant_id),
		       count(*) FILTER (WHERE definition_id IS NOT NULL),
		       count(*) FILTER (WHERE definition_id IS DISTINCT FROM vulnerability_id),
		       count(*) FILTER (WHERE updated_at <> $1)
		FROM findings`, defCatalogPast).Scan(&links, &primaryLinks, &wrongTenant, &defSet, &defMismatch, &touched)
	if links != s.linked || primaryLinks != s.linked || wrongTenant != 0 {
		t.Errorf("finding links: %d rows, %d primary, %d cross-tenant; want %d, %d, 0", links, primaryLinks, wrongTenant, s.linked, s.linked)
	}
	if defSet != s.linked || defMismatch != 0 {
		t.Errorf("findings.definition_id: %d set, %d differ from vulnerability_id; want %d, 0", defSet, defMismatch, s.linked)
	}
	if touched != 0 {
		t.Errorf("%d findings had updated_at moved by the backfill", touched)
	}

	// Nothing is left NOT VALID.
	var notValid []string
	rows, err := db.QueryContext(ctx, `
		SELECT conname FROM pg_constraint
		WHERE NOT convalidated
		  AND conrelid IN ('vulnerabilities'::regclass, 'findings'::regclass, 'finding_definitions'::regclass,
		                   'definition_identifiers'::regclass, 'definition_relations'::regclass,
		                   'definition_taxonomy'::regclass)
		  AND (conname LIKE 'chk_vuln_%' OR conname LIKE 'fk_vulnerabilities_%' OR conname LIKE 'fk_findings_definition%'
		       OR conname LIKE '%definition%')`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		notValid = append(notValid, n)
	}
	if len(notValid) > 0 {
		t.Errorf("constraints left NOT VALID: %v", notValid)
	}
}

func assertDefinitionCatalogReverted(ctx context.Context, t *testing.T, db *sql.DB, s defCatalogSeed) {
	t.Helper()
	var leftover int
	mustQueryRow(ctx, t, db, `
		SELECT count(*) FROM information_schema.columns
		WHERE (table_name = 'vulnerabilities' AND column_name IN ('tenant_id', 'scope_tenant_id', 'kind', 'namespace',
		        'external_id', 'lifecycle', 'merged_into', 'merged_into_scope', 'origin', 'cvss_version', 'nicknames'))
		   OR (table_name = 'findings' AND column_name = 'definition_id')`).Scan(&leftover)
	if leftover != 0 {
		t.Errorf("%d definition columns left after down", leftover)
	}
	var tables int
	mustQueryRow(ctx, t, db, `
		SELECT count(*) FROM information_schema.tables
		WHERE table_name IN ('definition_identifiers', 'definition_relations', 'taxonomy_entries',
		                     'definition_taxonomy', 'finding_definitions')`).Scan(&tables)
	if tables != 0 {
		t.Errorf("%d definition tables left after down", tables)
	}
	var nullable string
	mustQueryRow(ctx, t, db, `SELECT is_nullable FROM information_schema.columns
		WHERE table_name = 'vulnerabilities' AND column_name = 'cve_id'`).Scan(&nullable)
	if nullable != "NO" {
		t.Errorf("vulnerabilities.cve_id nullable=%s after down, want NOT NULL", nullable)
	}
	var vulns, linked int
	mustQueryRow(ctx, t, db, `SELECT (SELECT count(*) FROM vulnerabilities), count(vulnerability_id) FROM findings`).Scan(&vulns, &linked)
	if vulns != 3 || linked != s.linked {
		t.Errorf("after down: %d catalog rows, %d linked findings; want 3, %d", vulns, linked, s.linked)
	}
}

// mustQueryRow returns a row whose Scan fails the test on error.
func mustQueryRow(ctx context.Context, t *testing.T, db *sql.DB, query string, args ...any) fatalRow {
	t.Helper()
	return fatalRow{t: t, row: db.QueryRowContext(ctx, query, args...), query: query}
}

type fatalRow struct {
	t     *testing.T
	row   *sql.Row
	query string
}

func (r fatalRow) Scan(dest ...any) {
	r.t.Helper()
	if err := r.row.Scan(dest...); err != nil {
		r.t.Fatalf("query %q: %v", r.query, err)
	}
}
