package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// TestCreate_PersistsClassificationColumns verifies that the single-row
// Create() INSERT persists cvss_score, cvss_vector, cve_id, cwe_ids and
// owasp_ids. These columns were previously omitted from the INSERT column list,
// so a freshly-created pentest/manual finding lost its CVSS score+vector and
// CVE/CWE/OWASP classification until the first edit (only Update() wrote them) —
// a real correctness bug on the New Finding form's CVSS calculator.
//
// The finding is read back with GetByID WITHOUT any intervening Update, so a
// regression (columns dropped from the INSERT again) fails here. Skipped unless
// DATABASE_URL is set.
func TestCreate_PersistsClassificationColumns(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	repo := NewFindingRepository(&DB{DB: db})

	// Seeded org tenant (FK findings.tenant_id -> tenants.id).
	tenantID := seedTestTenant(ctx, t, db)

	// Pentest finding with no asset (asset_id NULL is allowed for pentest source),
	// carrying a full classification.
	const (
		wantVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
		wantCVE    = "CVE-2021-44228"
		wantCWE    = "CWE-89"
		wantOWASP  = "A03:2021"
	)
	wantScore := 9.8

	f, err := vulnerability.NewFinding(
		tenantID, shared.ID{},
		vulnerability.FindingSourcePentest, "pentest-manual",
		vulnerability.SeverityCritical, "classification persist check",
	)
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	if err := f.SetClassification(wantCVE, &wantScore, wantVector, []string{wantCWE}, []string{wantOWASP}); err != nil {
		t.Fatalf("set classification: %v", err)
	}
	f.SetFingerprint("test-create-classification-" + f.ID().String())

	if err := repo.Create(ctx, f); err != nil {
		t.Fatalf("create: %v", err)
	}
	defer func() { _ = repo.Delete(ctx, tenantID, f.ID()) }()

	// Read back WITHOUT any Update — this is the create-path round-trip.
	got, err := repo.GetByID(ctx, tenantID, f.ID())
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}

	if got.CVSSScore() == nil || *got.CVSSScore() != wantScore {
		t.Errorf("cvss_score not persisted on create: got %v, want %v", got.CVSSScore(), wantScore)
	}
	if got.CVSSVector() != wantVector {
		t.Errorf("cvss_vector not persisted on create: got %q, want %q", got.CVSSVector(), wantVector)
	}
	if got.CVEID() != wantCVE {
		t.Errorf("cve_id not persisted on create: got %q, want %q", got.CVEID(), wantCVE)
	}
	if len(got.CWEIDs()) != 1 || got.CWEIDs()[0] != wantCWE {
		t.Errorf("cwe_ids not persisted on create: got %v, want [%s]", got.CWEIDs(), wantCWE)
	}
	if len(got.OWASPIDs()) != 1 || got.OWASPIDs()[0] != wantOWASP {
		t.Errorf("owasp_ids not persisted on create: got %v, want [%s]", got.OWASPIDs(), wantOWASP)
	}
}
