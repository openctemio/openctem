package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The definition catalog's tenant isolation and trust rules are enforced by
// the schema (migrations 000820-000827), so a repository bug or a hand-written
// statement cannot link one tenant's finding to another tenant's definition or
// let a report write shared catalog content. These tests write SQL directly,
// as the API's least-privilege role, and expect the database to refuse.
// https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-044-issue-definitions-and-findings.md

const nilScope = "00000000-0000-0000-0000-000000000000"

// seedTenantDefinition stores a tenant-scoped definition (a custom nuclei
// template) and returns its id. It goes with the tenant on cleanup.
func seedTenantDefinition(ctx context.Context, t *testing.T, db *sql.DB, tenantID shared.ID, externalID string) string {
	t.Helper()
	var id string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO vulnerabilities (tenant_id, kind, namespace, external_id, title, origin)
		VALUES ($1, 'exposure', 'NUCLEI', $2, 'internal panel', 'report') RETURNING id`,
		tenantID.String(), externalID).Scan(&id); err != nil {
		t.Fatalf("seed tenant definition: %v", err)
	}
	return id
}

// seedGlobalDefinition stores a global, rule-catalog definition.
func seedGlobalDefinition(ctx context.Context, t *testing.T, db *sql.DB) string {
	t.Helper()
	var id string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO vulnerabilities (kind, namespace, external_id, title, origin)
		VALUES ('exposure', 'NUCLEI', 'git-config-' || gen_random_uuid(), 'exposed git config', 'rule_catalog')
		RETURNING id`).Scan(&id); err != nil {
		t.Fatalf("seed global definition: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM vulnerabilities WHERE id = $1`, id) })
	return id
}

func seedPlainFinding(ctx context.Context, t *testing.T, db *sql.DB, tenantID shared.ID) string {
	t.Helper()
	id := shared.NewID().String()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, status, fingerprint)
		VALUES ($1, $2, $3, 'dast', 'nuclei', 'm', 'high', 'new', $4)`,
		id, tenantID.String(), seedTestAsset(ctx, t, db, tenantID).String(), "defschema-"+id); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	return id
}

// pqCode is the SQLSTATE of err, or "" when it is not a database error.
func pqCode(err error) string {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return string(pqErr.Code)
	}
	return ""
}

const (
	sqlStateFK    = "23503"
	sqlStateCheck = "23514"
)

func expectSQLState(t *testing.T, what string, err error, want ...string) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: accepted, want SQLSTATE %v", what, want)
		return
	}
	got := pqCode(err)
	for _, w := range want {
		if got == w {
			return
		}
	}
	t.Errorf("%s: %v (SQLSTATE %s), want %v", what, err, got, want)
}

func linkFinding(ctx context.Context, db *sql.DB, findingID, tenantID, definitionID, definitionScope, role string, ord int) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO finding_definitions (finding_id, tenant_id, definition_id, definition_scope, role, ord, asserted_by)
		VALUES ($1, $2, $3, $4, $5, $6, 'report')`, findingID, tenantID, definitionID, definitionScope, role, ord)
	return err
}

func TestDefinitionSchema_FindingLinkStaysInTenant(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	tA, tB := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	defB := seedTenantDefinition(ctx, t, db, tB, "b-internal-panel")
	defA := seedTenantDefinition(ctx, t, db, tA, "a-internal-panel")
	global := seedGlobalDefinition(ctx, t, db)
	fA := seedPlainFinding(ctx, t, db, tA)

	// Another tenant's definition, whatever scope the writer claims.
	expectSQLState(t, "link to B's definition claiming B's scope",
		linkFinding(ctx, db, fA, tA.String(), defB, tB.String(), "primary", 0), sqlStateCheck)
	expectSQLState(t, "link to B's definition claiming A's scope",
		linkFinding(ctx, db, fA, tA.String(), defB, tA.String(), "primary", 0), sqlStateFK)
	expectSQLState(t, "link to B's definition claiming global scope",
		linkFinding(ctx, db, fA, tA.String(), defB, nilScope, "primary", 0), sqlStateFK)
	// A finding of A filed under tenant B.
	expectSQLState(t, "A's finding linked under tenant B",
		linkFinding(ctx, db, fA, tB.String(), defB, tB.String(), "primary", 0), sqlStateFK)
	// A global definition claimed as tenant-scoped.
	expectSQLState(t, "global definition with a tenant scope",
		linkFinding(ctx, db, fA, tA.String(), global, tA.String(), "primary", 0), sqlStateFK)

	// The legitimate links.
	if err := linkFinding(ctx, db, fA, tA.String(), global, nilScope, "primary", 0); err != nil {
		t.Fatalf("link to a global definition: %v", err)
	}
	if err := linkFinding(ctx, db, fA, tA.String(), defA, tA.String(), "detected_by", 1); err != nil {
		t.Fatalf("link to the tenant's own definition: %v", err)
	}

	// ord 0 <=> primary.
	expectSQLState(t, "a second primary at ord 2",
		linkFinding(ctx, db, fA, tA.String(), seedTenantDefinition(ctx, t, db, tA, "a-other"), tA.String(), "primary", 2), sqlStateCheck)
}

func TestDefinitionSchema_FindingPrimaryMustBeItsOwnLink(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	tA, tB := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	defB := seedTenantDefinition(ctx, t, db, tB, "b-panel")
	global := seedGlobalDefinition(ctx, t, db)
	fA := seedPlainFinding(ctx, t, db, tA)

	// definition_id naming another tenant's definition, or a definition the
	// finding is not linked to, fails (the key is deferred: at commit).
	for name, def := range map[string]string{"B's definition": defB, "an unlinked global definition": global} {
		_, err := db.ExecContext(ctx, `UPDATE findings SET definition_id = $1 WHERE tenant_id = $2 AND id = $3`, def, tA.String(), fA)
		expectSQLState(t, "findings.definition_id = "+name, err, sqlStateFK)
	}

	// Linked first, in one transaction in either order: accepted.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE findings SET definition_id = $1 WHERE tenant_id = $2 AND id = $3`, global, tA.String(), fA); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO finding_definitions (finding_id, tenant_id, definition_id, definition_scope, role, ord, asserted_by)
		VALUES ($1, $2, $3, $4, 'primary', 0, 'report')`, fA, tA.String(), global, nilScope); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("primary set together with its link: %v", err)
	}

	// Deleting the definition removes the link and clears the pointer in one statement.
	if _, err := db.ExecContext(ctx, `DELETE FROM vulnerabilities WHERE id = $1`, global); err != nil {
		t.Fatalf("delete a linked definition: %v", err)
	}
	var def sql.NullString
	var links int
	if err := db.QueryRowContext(ctx, `SELECT definition_id, (SELECT count(*) FROM finding_definitions WHERE finding_id = $1)
		FROM findings WHERE id = $1`, fA).Scan(&def, &links); err != nil {
		t.Fatal(err)
	}
	if def.Valid || links != 0 {
		t.Errorf("after the definition was deleted: definition_id=%v, %d links", def, links)
	}
}

func TestDefinitionSchema_ScopeIsFixedAndCVEsAreGlobal(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	tA := seedTestTenant(ctx, t, db)
	defA := seedTenantDefinition(ctx, t, db, tA, "a-panel")
	global := seedGlobalDefinition(ctx, t, db)

	_, err := db.ExecContext(ctx, `UPDATE vulnerabilities SET tenant_id = NULL WHERE id = $1`, defA)
	expectSQLState(t, "publish a tenant definition as global", err, sqlStateCheck)
	_, err = db.ExecContext(ctx, `UPDATE vulnerabilities SET tenant_id = $1 WHERE id = $2`, tA.String(), global)
	expectSQLState(t, "take a global definition into a tenant", err, sqlStateCheck)

	cve := uniqueCVE()
	_, err = db.ExecContext(ctx, `
		INSERT INTO vulnerabilities (tenant_id, namespace, external_id, cve_id, title, origin)
		VALUES ($1, 'CVE', $2, $2, 't', 'report')`, tA.String(), cve)
	expectSQLState(t, "a tenant-scoped CVE", err, sqlStateCheck)
	_, err = db.ExecContext(ctx, `
		INSERT INTO vulnerabilities (namespace, external_id, title, origin) VALUES ('CVE', $1, 't', 'report')`, cve)
	expectSQLState(t, "a CVE definition without cve_id", err, sqlStateCheck)
	_, err = db.ExecContext(ctx, `
		INSERT INTO vulnerabilities (namespace, external_id, title, origin) VALUES ('NUCLEI', 'x-' || gen_random_uuid(), 't', 'tenant')`)
	expectSQLState(t, "a global definition with origin tenant", err, sqlStateCheck)

	// Merged into another tenant's definition.
	tB := seedTestTenant(ctx, t, db)
	defB := seedTenantDefinition(ctx, t, db, tB, "b-panel")
	_, err = db.ExecContext(ctx, `UPDATE vulnerabilities SET lifecycle = 'merged', merged_into = $1, merged_into_scope = $2 WHERE id = $3`,
		defB, tA.String(), defA)
	expectSQLState(t, "merge into another tenant's definition (claiming own scope)", err, sqlStateFK)
	_, err = db.ExecContext(ctx, `UPDATE vulnerabilities SET lifecycle = 'merged', merged_into = $1, merged_into_scope = $2 WHERE id = $3`,
		defB, tB.String(), defA)
	expectSQLState(t, "merge into another tenant's definition (claiming its scope)", err, sqlStateCheck)
	if _, err := db.ExecContext(ctx, `UPDATE vulnerabilities SET lifecycle = 'merged', merged_into = $1, merged_into_scope = $2 WHERE id = $3`,
		global, nilScope, defA); err != nil {
		t.Errorf("merge a tenant definition into a global one: %v", err)
	}
}

// The code deployed before this release inserts catalog rows with cve_id
// only; the row must come out as a complete global CVE definition.
func TestDefinitionSchema_LegacyCVEInsertIsACompleteDefinition(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	cve := uniqueCVE()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM vulnerabilities WHERE cve_id = $1`, cve)
	})

	repo := NewVulnerabilityRepository(&DB{DB: db})
	if err := repo.UpsertBatchByCVE(ctx, []*vulnerability.Vulnerability{sensorReportedVuln(t, cve)}); err != nil {
		t.Fatal(err)
	}
	var ns, ext, kind, origin, lifecycle, scope string
	var tenant sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT namespace, external_id, kind, origin, lifecycle, scope_tenant_id, tenant_id
		FROM vulnerabilities WHERE cve_id = $1`, cve).Scan(&ns, &ext, &kind, &origin, &lifecycle, &scope, &tenant); err != nil {
		t.Fatal(err)
	}
	if ns != "CVE" || ext != cve || kind != "vulnerability" || origin != "report" || lifecycle != "published" ||
		scope != nilScope || tenant.Valid {
		t.Errorf("legacy insert: %s/%s kind=%s origin=%s lifecycle=%s scope=%s tenant=%v", ns, ext, kind, origin, lifecycle, scope, tenant)
	}
}

func TestDefinitionSchema_ReportsCannotWriteSharedContent(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	tA, tB := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	global := seedGlobalDefinition(ctx, t, db)
	other := seedGlobalDefinition(ctx, t, db)
	defA := seedTenantDefinition(ctx, t, db, tA, "a-panel")
	defB := seedTenantDefinition(ctx, t, db, tB, "b-panel")

	addIdentifier := func(tenant any, scope, def, assertedBy string, primary bool) error {
		_, err := db.ExecContext(ctx, `
			INSERT INTO definition_identifiers (namespace, external_id, tenant_id, scope_tenant_id, definition_id, is_primary, asserted_by)
			VALUES ('GHSA', 'GHSA-' || gen_random_uuid(), $1, $2, $3, $4, $5)`, tenant, scope, def, primary, assertedBy)
		return err
	}
	expectSQLState(t, "a report asserting a global alias", addIdentifier(nil, nilScope, global, "report", false), sqlStateCheck)
	expectSQLState(t, "a tenant asserting a global alias", addIdentifier(nil, nilScope, global, "tenant", false), sqlStateCheck)
	expectSQLState(t, "a tenant identifier on a global definition", addIdentifier(tA.String(), tA.String(), global, "report", false), sqlStateFK)
	expectSQLState(t, "A's identifier on B's definition", addIdentifier(tA.String(), tA.String(), defB, "report", false), sqlStateFK)
	if err := addIdentifier(nil, nilScope, global, "osv", false); err != nil {
		t.Errorf("an OSV alias on a global definition: %v", err)
	}
	if err := addIdentifier(tA.String(), tA.String(), defA, "report", false); err != nil {
		t.Errorf("a tenant alias on its own definition: %v", err)
	}

	addRelation := func(tenant any, scope, from, fromScope, to, toScope, assertedBy string) error {
		_, err := db.ExecContext(ctx, `
			INSERT INTO definition_relations (tenant_id, scope_tenant_id, from_id, from_scope, to_id, to_scope, relation, asserted_by)
			VALUES ($1, $2, $3, $4, $5, $6, 'detects', $7)`, tenant, scope, from, fromScope, to, toScope, assertedBy)
		return err
	}
	expectSQLState(t, "a report asserting a global relation", addRelation(nil, nilScope, global, nilScope, other, nilScope, "report"), sqlStateCheck)
	expectSQLState(t, "a global relation to a tenant definition", addRelation(nil, nilScope, global, nilScope, defA, tA.String(), "osv"), sqlStateCheck)
	expectSQLState(t, "A's relation to B's definition", addRelation(tA.String(), tA.String(), defA, tA.String(), defB, tB.String(), "report"), sqlStateCheck)
	expectSQLState(t, "A's relation to B's definition (claiming A's scope)", addRelation(tA.String(), tA.String(), defA, tA.String(), defB, tA.String(), "report"), sqlStateFK)
	if err := addRelation(tA.String(), tA.String(), defA, tA.String(), global, nilScope, "report"); err != nil {
		t.Errorf("A's own template detecting a global definition: %v", err)
	}

	addTaxonomy := func(tenant any, scope, def, assertedBy string) error {
		_, err := db.ExecContext(ctx, `
			INSERT INTO definition_taxonomy (definition_id, tenant_id, scope_tenant_id, namespace, external_id, asserted_by)
			VALUES ($1, $2, $3, 'CWE', 'CWE-' || (random() * 100000)::int, $4)`, def, tenant, scope, assertedBy)
		return err
	}
	expectSQLState(t, "a report mapping a global definition to a CWE", addTaxonomy(nil, nilScope, global, "report"), sqlStateCheck)
	expectSQLState(t, "A mapping B's definition", addTaxonomy(tA.String(), tA.String(), defB, "report"), sqlStateFK)
	if err := addTaxonomy(nil, nilScope, global, "kev"); err != nil {
		t.Errorf("the KEV feed mapping a global definition: %v", err)
	}
	if err := addTaxonomy(tA.String(), tA.String(), defA, "report"); err != nil {
		t.Errorf("a tenant mapping its own definition: %v", err)
	}
}
