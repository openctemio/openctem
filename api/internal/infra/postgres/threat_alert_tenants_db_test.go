package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// One lookup answers a page of vulnerabilities: an open finding counts, a
// closed one does not, an asset running a named product counts only while
// its version is unknown, and a vulnerability nobody has gets no key.
// Requires DATABASE_URL.
func TestThreatAlertTenantsAffectedBy_DB(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	const cveF, cveS, cveClosed, cveNone = "CVE-2097-0001", "CVE-2097-0002", "CVE-2097-0003", "CVE-2097-0004"
	cleanup := func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM vulnerability_affected WHERE cve_id LIKE 'CVE-2097-%';
			DELETE FROM cve_records WHERE cve_id LIKE 'CVE-2097-%'`)
	}
	cleanup()
	t.Cleanup(cleanup)
	tA, tB, tC := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	aA, aB, aC := seedTestAsset(ctx, t, db, tA), seedTestAsset(ctx, t, db, tB), seedTestAsset(ctx, t, db, tC)

	finding := func(tenant, asset shared.ID, cve, status string) {
		t.Helper()
		exec(`INSERT INTO findings (tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, cve_id)
			VALUES ($1, $2, 'sca', 'test', 'm', 'high', $3, $4, $5)`,
			tenant.String(), asset.String(), "fp-"+shared.NewID().String(), status, cve)
	}
	finding(tA, aA, cveF, "new")
	finding(tB, aB, cveClosed, "resolved")

	product, unknownV, knownV := shared.NewID(), shared.NewID(), shared.NewID()
	exec(`INSERT INTO software_products (id, part, vendor, name, source) VALUES ($1, 'a', 'example', $2, 'curated')`,
		product.String(), "prod-"+product.String()[:8])
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM software_products WHERE id = $1`, product.String())
	})
	exec(`INSERT INTO software_versions (id, product_id, raw, normalized) VALUES ($1, $2, '', NULL), ($3, $2, '2.0.1', '2.0.1')`,
		unknownV.String(), product.String(), knownV.String())
	exec(`INSERT INTO cve_records (cve_id, status) VALUES ($1, 'Analyzed')`, cveS)
	exec(`INSERT INTO vulnerability_affected (cve_id, product_id, scheme, v_end) VALUES ($1, $2, 'semver', '3.0.0')`, cveS, product.String())
	// B runs the product with an unknown version (possible); C with a known
	// one (the matcher decides, not the planner's fan-out).
	exec(`INSERT INTO asset_software (tenant_id, asset_id, product_id, software_version_id, location, source, confidence)
		VALUES ($1, $2, $3, $4, '', 'technology', 80), ($5, $6, $3, $7, '', 'technology', 80)`,
		tB.String(), aB.String(), product.String(), unknownV.String(), tC.String(), aC.String(), knownV.String())

	repo := NewThreatAlertRepository(&DB{DB: db})
	got, err := repo.TenantsAffectedBy(ctx, []string{cveF, cveS, cveClosed, cveNone, cveF})
	if err != nil {
		t.Fatal(err)
	}
	if len(got[cveF]) != 1 || got[cveF][0] != tA {
		t.Fatalf("%s -> %v, want only A", cveF, got[cveF])
	}
	if len(got[cveS]) != 1 || got[cveS][0] != tB {
		t.Fatalf("%s -> %v, want only B (unknown version)", cveS, got[cveS])
	}
	if _, ok := got[cveClosed]; ok {
		t.Fatalf("a closed finding fanned out: %v", got[cveClosed])
	}
	if _, ok := got[cveNone]; ok {
		t.Fatal("a vulnerability nobody has got a key")
	}
	if empty, err := repo.TenantsAffectedBy(ctx, nil); err != nil || len(empty) != 0 {
		t.Fatalf("no ids: %v %v", empty, err)
	}
}
