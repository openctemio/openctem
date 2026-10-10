package integration

// Migration components_on_software_catalog (RFC-070): the legacy global
// components table and the per-tenant asset_components rows move into the
// software catalog, per tenant. Two tenants sharing one global component
// get one private version each; a tenant's private package never becomes a
// global row; findings point at their own tenant's version; the parent of a
// legacy row becomes a graph edge; the down migration restores the legacy
// tables.
//
// Runs on a private database: everything up, this migration down (recreates
// the legacy tables), seed legacy rows, this migration up, down, up.

import (
	"math"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigrationComponentsOnSoftwareCatalog(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migcomponents", dir)
	v := testdb.MigrationVersion(t, dir, "components_on_software_catalog")
	// Everything above this migration comes down first, then this one.
	testdb.Migrate(t, db, dir, v, math.MaxInt32, true)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := db.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	const (
		tA, tB         = "a1111111-1111-4111-8111-111111111111", "b2222222-2222-4222-8222-222222222222"
		assetA, assetB = "a1111111-0000-4000-8000-0000000000a1", "b2222222-0000-4000-8000-0000000000b1"
		lodash         = "c0000000-0000-4000-8000-000000000001"
		private        = "c0000000-0000-4000-8000-000000000002"
		log4j          = "c0000000-0000-4000-8000-000000000003"
		linkLodash     = "d0000000-0000-4000-8000-0000000000a1"
		linkPrivate    = "d0000000-0000-4000-8000-0000000000a2"
	)
	exec(`INSERT INTO tenants (id, slug, name) VALUES ($1, 'mig-comp-a', 'a'), ($2, 'mig-comp-b', 'b')`, tA, tB)
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'repo-a', 'repository'), ($3, $4, 'repo-b', 'repository')`,
		assetA, tA, assetB, tB)
	exec(`INSERT INTO components (id, purl, name, version, ecosystem) VALUES
		($1, 'pkg:npm/lodash@4.17.20', 'lodash', '4.17.20', 'npm'),
		($2, 'pkg:npm/%40acme/internal-auth@1.2.0', '@acme/internal-auth', '1.2.0', 'npm'),
		($3, 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1', 'log4j-core', '2.14.1', 'maven')`, lodash, private, log4j)
	exec(`INSERT INTO asset_components (id, tenant_id, asset_id, component_id, name, version, ecosystem, purl, dependency_type,
		depth, is_direct, license, manifest_path, parent_component_id) VALUES
		($1, $3, $4, $5, 'lodash', '4.17.20', 'npm', 'pkg:npm/lodash@4.17.20', 'direct', 0, true, 'MIT', 'package-lock.json', NULL),
		($2, $3, $4, $6, '@acme/internal-auth', '1.2.0', 'npm', 'pkg:npm/%40acme/internal-auth@1.2.0', 'dev', 1, false, 'MIT, Apache-2.0', 'package-lock.json', $1)`,
		linkLodash, linkPrivate, tA, assetA, lodash, private)
	exec(`INSERT INTO asset_components (tenant_id, asset_id, component_id, name, version, ecosystem, purl, dependency_type, manifest_path)
		VALUES ($1, $2, $3, 'lodash', '4.17.20', 'npm', 'pkg:npm/lodash@4.17.20', 'direct', 'package-lock.json')`, tB, assetB, lodash)
	exec(`INSERT INTO findings (tenant_id, asset_id, component_id, tool_name, message, severity, fingerprint, source, status) VALUES
		($1, $2, $3, 'trivy', 'm', 'high', 'mig-fa', 'sca', 'new'),
		($4, $5, $3, 'trivy', 'm', 'high', 'mig-fb', 'sca', 'new'),
		($4, $5, $6, 'trivy', 'm', 'critical', 'mig-fb2', 'sca', 'new')`, tA, assetA, lodash, tB, assetB, log4j)

	testdb.Migrate(t, db, dir, v, v, false)

	if n := count(`SELECT count(*) FROM software_products WHERE purl_type IS NOT NULL AND tenant_id IS NULL`); n != 0 {
		t.Fatalf("%d global package products; every copied package must be tenant-private", n)
	}
	if n := count(`SELECT count(*) FROM software_products WHERE purl_name = 'internal-auth' AND tenant_id <> $1`, tA); n != 0 {
		t.Fatal("tenant A's private package reached another tenant")
	}
	if n := count(`SELECT count(*) FROM software_products WHERE purl_type = 'npm' AND purl_namespace = '@acme' AND purl_name = 'internal-auth' AND tenant_id = $1`, tA); n != 1 {
		t.Fatalf("the scoped npm package was not decoded: %d", n)
	}
	if n := count(`SELECT count(*) FROM software_versions WHERE purl = 'pkg:npm/lodash@4.17.20'`); n != 2 {
		t.Fatalf("lodash versions = %d, want one per tenant", n)
	}
	// Each finding points at its own tenant's version (also the log4j finding
	// whose tenant had no link to it).
	if n := count(`SELECT count(*) FROM findings f JOIN software_versions v ON v.id = f.component_id
		WHERE f.fingerprint IN ('mig-fa', 'mig-fb', 'mig-fb2') AND v.tenant_id = f.tenant_id`); n != 3 {
		t.Fatalf("findings on their own tenant's version = %d, want 3", n)
	}
	if n := count(`SELECT count(*) FROM asset_software WHERE source = 'package'`); n != 3 {
		t.Fatalf("package links = %d, want 3", n)
	}
	var rel, scope, lic string
	if err := db.QueryRow(`SELECT relationship, COALESCE(dep_scope, ''), array_to_string(licenses, ',') FROM asset_software s
		JOIN software_versions v ON v.id = s.software_version_id WHERE v.purl = 'pkg:npm/@acme/internal-auth@1.2.0'`).Scan(&rel, &scope, &lic); err != nil {
		t.Fatal(err)
	}
	if rel != "transitive" || scope != "development" || lic != "Apache-2.0,MIT" {
		t.Fatalf("private link = %s %s %s", rel, scope, lic)
	}
	if n := count(`SELECT count(*) FROM asset_software_edges WHERE tenant_id = $1`, tA); n != 1 {
		t.Fatalf("edges = %d, want the legacy parent as one edge", n)
	}
	// A finding cannot point at another tenant's private version.
	var privateVersion string
	if err := db.QueryRow(`SELECT id FROM software_versions WHERE purl = 'pkg:npm/@acme/internal-auth@1.2.0'`).Scan(&privateVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO findings (tenant_id, asset_id, component_id, tool_name, message, severity, fingerprint, source)
		VALUES ($1, $2, $3, 'x', 'm', 'low', 'mig-cross', 'sca')`, tB, assetB, privateVersion); err == nil {
		t.Fatal("tenant B's finding was allowed to name tenant A's private package version")
	}

	// Down restores the legacy tables; up again converts them again.
	testdb.Migrate(t, db, dir, v, v, true)
	if n := count(`SELECT count(*) FROM components`); n != 3 {
		t.Fatalf("components after down = %d, want 3", n)
	}
	if n := count(`SELECT count(*) FROM asset_components`); n != 3 {
		t.Fatalf("asset_components after down = %d, want 3", n)
	}
	if n := count(`SELECT count(*) FROM findings f JOIN components c ON c.id = f.component_id WHERE f.fingerprint LIKE 'mig-f%'`); n != 3 {
		t.Fatalf("findings with a component after down = %d, want 3", n)
	}
	testdb.Migrate(t, db, dir, v, v, false)
	if n := count(`SELECT count(*) FROM asset_software WHERE source = 'package'`); n != 3 {
		t.Fatalf("package links after down and up = %d, want 3", n)
	}
}
