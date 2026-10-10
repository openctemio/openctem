package testdb

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
)

// SeedPackageVersion makes sure the software catalog holds the package
// version a canonical package URL names ("pkg:npm/lodash@4.17.21") and
// returns its product and version ids. tenantID "" makes a global row (as the
// vulnerability feed does); otherwise the rows are private to that tenant.
// The URL must be canonical: lower-case type, no qualifiers.
func SeedPackageVersion(t testing.TB, db *sql.DB, tenantID, purl string) (productID, versionID string) {
	t.Helper()
	body := strings.TrimPrefix(purl, "pkg:")
	version := ""
	if at := strings.LastIndexByte(body, '@'); at > strings.LastIndexByte(body, '/') {
		version, body = body[at+1:], body[:at]
	}
	segs := strings.Split(body, "/")
	if len(segs) < 2 {
		t.Fatalf("testdb: %q is not a package URL", purl)
	}
	typ, name, ns := segs[0], segs[len(segs)-1], strings.Join(segs[1:len(segs)-1], "/")
	var tenant any
	source := "osv"
	if tenantID != "" {
		tenant, source = tenantID, "observed"
	}
	err := db.QueryRow(`
		SELECT id FROM software_products
		WHERE purl_type = $1 AND purl_namespace = $2 AND purl_name = $3 AND tenant_id IS NOT DISTINCT FROM $4::uuid`,
		typ, ns, name, tenant).Scan(&productID)
	if errors.Is(err, sql.ErrNoRows) {
		err = db.QueryRow(`
			INSERT INTO software_products (tenant_id, part, name, purl_type, purl_namespace, purl_name, source)
			VALUES ($4, 'a', $3, $1, $2, $3, $5) RETURNING id`, typ, ns, name, tenant, source).Scan(&productID)
	}
	if err != nil {
		t.Fatalf("testdb: package %s: %v", purl, err)
	}
	scheme := map[string]string{"npm": "npm", "pypi": "pep440", "maven": "maven", "golang": "go"}[typ]
	if scheme == "" {
		scheme = "generic"
	}
	err = db.QueryRow(`
		SELECT id FROM software_versions
		WHERE product_id = $1 AND scheme = $2 AND COALESCE(normalized, 'raw:' || raw) = COALESCE(NULLIF($3, ''), 'raw:' || $3)
		  AND qualifier = '' AND edition = ''`, productID, scheme, version).Scan(&versionID)
	if errors.Is(err, sql.ErrNoRows) {
		err = db.QueryRow(`
			INSERT INTO software_versions (product_id, tenant_id, raw, normalized, scheme, purl)
			VALUES ($1, $2, $3, NULLIF($3, ''), $4, $5) RETURNING id`, productID, tenant, version, scheme, purl).Scan(&versionID)
	}
	if err != nil {
		t.Fatalf("testdb: package version %s: %v", purl, err)
	}
	return productID, versionID
}

// SeedPackageLink records that an asset uses a package version at a
// location and returns the link id.
func SeedPackageLink(t testing.TB, db *sql.DB, tenantID, assetID, productID, versionID, location, relationship string) string {
	t.Helper()
	var id string
	if err := db.QueryRow(`
		INSERT INTO asset_software (tenant_id, asset_id, product_id, software_version_id, location, source,
			confidence, relationship)
		VALUES ($1, $2, $3, $4, $5, 'package', 100, $6)
		ON CONFLICT ON CONSTRAINT uq_asset_software DO UPDATE SET last_seen_at = now()
		RETURNING id`, tenantID, assetID, productID, versionID, location, relationship).Scan(&id); err != nil {
		t.Fatalf("testdb: package link: %v", err)
	}
	return id
}

// InsertPackageVersion is SeedPackageVersion for a version id the test
// chose; the package URL must name a version not seeded yet.
func InsertPackageVersion(t testing.TB, db *sql.DB, tenantID, versionID, purl string) {
	t.Helper()
	at := strings.LastIndexByte(purl, '@')
	if at < 0 {
		t.Fatalf("testdb: %q has no version", purl)
	}
	productID, _ := SeedPackageVersion(t, db, tenantID, purl[:at])
	var tenant any
	if tenantID != "" {
		tenant = tenantID
	}
	if _, err := db.Exec(`
		INSERT INTO software_versions (id, product_id, tenant_id, raw, normalized, scheme, purl)
		SELECT $1, $2, $3, $4, $4, CASE p.purl_type WHEN 'npm' THEN 'npm' WHEN 'pypi' THEN 'pep440'
			WHEN 'maven' THEN 'maven' WHEN 'golang' THEN 'go' ELSE 'generic' END, $5
		FROM software_products p WHERE p.id = $2`,
		versionID, productID, tenant, purl[at+1:], purl); err != nil {
		t.Fatalf("testdb: package version %s: %v", purl, err)
	}
}
