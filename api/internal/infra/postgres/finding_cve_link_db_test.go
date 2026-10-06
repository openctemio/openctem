package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// seedUnlinkedCVEFinding stores a finding with the given cve_id and no catalog link.
func seedUnlinkedCVEFinding(ctx context.Context, t *testing.T, db *sql.DB, tenantID, assetID shared.ID, cve string) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, status, fingerprint, cve_id)
		VALUES ($1, $2, $3, 'sca', 'trivy', 'm', 'high', 'new', $4, $5)`,
		id.String(), tenantID.String(), assetID.String(), "cvelink-fp-"+id.String(), cve); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	return id
}

func readCVELink(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID) (cve sql.NullString, vulnID sql.NullString) {
	t.Helper()
	if err := db.QueryRowContext(ctx, `SELECT cve_id, vulnerability_id FROM findings WHERE id = $1`, id.String()).
		Scan(&cve, &vulnID); err != nil {
		t.Fatalf("read finding: %v", err)
	}
	return cve, vulnID
}

// A finding stored before its CVE had a catalog entry (protocol v2 never
// creates entries; a manual or pentest finding never looked one up) stayed
// unlinked forever. The catalog step now links such findings, in every tenant,
// when a batch names the CVE.
func TestLinkUnlinkedFindings_DB(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	cve := uniqueCVE()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM vulnerabilities WHERE cve_id = $1`, cve)
	})
	tA, tB := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	fA := seedUnlinkedCVEFinding(ctx, t, db, tA, seedTestAsset(ctx, t, db, tA), cve)
	fB := seedUnlinkedCVEFinding(ctx, t, db, tB, seedTestAsset(ctx, t, db, tB), cve)
	other := seedUnlinkedCVEFinding(ctx, t, db, tA, seedTestAsset(ctx, t, db, tA), uniqueCVE())

	repo := NewVulnerabilityRepository(&DB{DB: db})
	v := sensorReportedVuln(t, cve)
	if err := repo.UpsertBatchByCVE(ctx, []*vulnerability.Vulnerability{v}); err != nil {
		t.Fatal(err)
	}
	n, err := repo.LinkUnlinkedFindings(ctx, []string{cve})
	if err != nil {
		t.Fatalf("LinkUnlinkedFindings: %v", err)
	}
	if n != 2 {
		t.Errorf("linked %d findings, want 2", n)
	}
	for name, id := range map[string]shared.ID{"tenant A": fA, "tenant B": fB} {
		if _, link := readCVELink(ctx, t, db, id); link.String != v.ID().String() {
			t.Errorf("%s: vulnerability_id %q, want %s", name, link.String, v.ID())
		}
	}
	if _, link := readCVELink(ctx, t, db, other); link.Valid {
		t.Errorf("finding of another CVE got linked to %s", link.String)
	}
	// Idempotent: nothing left to link.
	if n, err := repo.LinkUnlinkedFindings(ctx, []string{cve}); err != nil || n != 0 {
		t.Errorf("second run linked %d (%v), want 0", n, err)
	}
}
