package postgres

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// A rescan that sees a finding with the same scanner output and the same
// template provenance must not write the finding again: each of the two side
// writes used to add a row version (99 indexes, non-HOT) per re-seen finding.
func TestResight_SameEvidenceAndProvenanceWriteNothing(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	asset := seedTestAsset(ctx, t, db, tenant)
	otherAsset := seedTestAsset(ctx, t, db, other)
	repo := NewFindingRepository(&DB{DB: db})

	const fp = "fp-resight-1"
	seed := func(tenantID, assetID shared.ID) shared.ID {
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `
			INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1,$2,$3,'dast','nuclei','m','high',$4,'new')`,
			id.String(), tenantID.String(), assetID.String(), fp); err != nil {
			t.Fatalf("seed finding: %v", err)
		}
		return id
	}
	id := seed(tenant, asset)
	otherID := seed(other, otherAsset)
	xmin := func(fid shared.ID) string {
		t.Helper()
		var x string
		if err := db.QueryRowContext(ctx, `SELECT xmin::text FROM findings WHERE id = $1`, fid.String()).Scan(&x); err != nil {
			t.Fatal(err)
		}
		return x
	}

	ev := []vulnerability.ScannerEvidenceUpdate{{Fingerprint: fp, Output: "GET / HTTP/1.1 200", CVSSv3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}
	prov := []vulnerability.TemplateSighting{{Fingerprint: fp, Provenance: vulnerability.TemplateProvenance{
		TemplateDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		TemplatePath:   "http/exposures/x.yaml", TemplatesVersion: "v10.1.0"}}}

	// First sighting writes both.
	if n, err := repo.UpdateScannerEvidenceBatch(ctx, tenant, ev); err != nil || n != 1 {
		t.Fatalf("first evidence write: n=%d err=%v", n, err)
	}
	if n, err := repo.RecordTemplateSightings(ctx, tenant, prov); err != nil || n != 1 {
		t.Fatalf("first provenance write: n=%d err=%v", n, err)
	}
	x1 := xmin(id)

	// An identical re-sighting writes nothing.
	if n, err := repo.UpdateScannerEvidenceBatch(ctx, tenant, ev); err != nil || n != 0 {
		t.Fatalf("identical evidence rewrote %d rows (err %v)", n, err)
	}
	if n, err := repo.RecordTemplateSightings(ctx, tenant, prov); err != nil || n != 0 {
		t.Fatalf("identical provenance rewrote %d rows (err %v)", n, err)
	}
	if x2 := xmin(id); x2 != x1 {
		t.Fatalf("finding row version moved on an identical re-sighting (%s -> %s)", x1, x2)
	}

	// Changed content still writes, and only in the finding's own tenant.
	ev[0].Output = "GET / HTTP/1.1 500"
	if n, err := repo.UpdateScannerEvidenceBatch(ctx, tenant, ev); err != nil || n != 1 {
		t.Fatalf("changed output: n=%d err=%v", n, err)
	}
	prov[0].Provenance.TemplatesVersion = "v10.2.0"
	if n, err := repo.RecordTemplateSightings(ctx, tenant, prov); err != nil || n != 1 {
		t.Fatalf("changed provenance: n=%d err=%v", n, err)
	}
	var out sql.NullString
	var ver sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT scanner_output, templates_version FROM findings WHERE id = $1`, id.String()).Scan(&out, &ver); err != nil {
		t.Fatal(err)
	}
	if out.String != "GET / HTTP/1.1 500" || ver.String != "v10.2.0" {
		t.Fatalf("changed values not stored: %q %q", out.String, ver.String)
	}
	var untouched sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT scanner_output FROM findings WHERE id = $1`, otherID.String()).Scan(&untouched); err != nil {
		t.Fatal(err)
	}
	if untouched.Valid {
		t.Fatal("another tenant's finding with the same fingerprint was written")
	}
}
