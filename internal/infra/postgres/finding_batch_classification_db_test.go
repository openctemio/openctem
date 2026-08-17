package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// The multi-row batch insert header used by scanner ingest omitted the
// denormalized classification columns (cve_id, cvss_score, cvss_vector,
// cwe_ids, owasp_ids) that the single-row Create writes. Scanner findings —
// which ingest through the batch path — therefore persisted with NULL/empty
// classification on first sight and were under-reported by groupByCVE / the
// CVE filter until a later re-ingest backfilled them. This guards that the
// batch path now persists them on the first sighting and refreshes them on
// re-ingest.

func openClassDB(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping classification-column DB test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return db
}

func TestCreateBatch_PersistsClassificationColumns(t *testing.T) {
	ctx := context.Background()
	db := openClassDB(t)
	repo := NewFindingRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)

	fingerprint := "class-cols-probe"
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM findings WHERE tenant_id = $1 AND fingerprint = $2`, tenantID.String(), fingerprint)
	})

	score := 9.8
	mkFinding := func(t *testing.T, cvss float64) *vulnerability.Finding {
		t.Helper()
		f, err := vulnerability.NewFinding(
			tenantID, assetID,
			vulnerability.FindingSourceVA, // scanner source → batch ingest path
			"probe-scanner",
			vulnerability.SeverityHigh,
			"probe message",
		)
		if err != nil {
			t.Fatalf("new finding: %v", err)
		}
		f.SetFingerprint(fingerprint)
		if err := f.SetClassification("CVE-2024-9999", &cvss, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			[]string{"CWE-79", "CWE-89"}, []string{"A03:2021"}); err != nil {
			t.Fatalf("set classification: %v", err)
		}
		return f
	}

	// First sighting via the batch path.
	if err := repo.CreateBatch(ctx, []*vulnerability.Finding{mkFinding(t, score)}); err != nil {
		t.Fatalf("first ingest: %v", err)
	}

	read := func() (cve sql.NullString, cvss sql.NullFloat64, vec sql.NullString, cwes, owasps pq.StringArray) {
		t.Helper()
		if err := db.QueryRowContext(ctx,
			`SELECT cve_id, cvss_score, cvss_vector, cwe_ids, owasp_ids
			 FROM findings WHERE tenant_id = $1 AND fingerprint = $2`,
			tenantID.String(), fingerprint).Scan(&cve, &cvss, &vec, &cwes, &owasps); err != nil {
			t.Fatalf("read classification: %v", err)
		}
		return
	}

	cve, cvss, vec, cwes, owasps := read()
	if !cve.Valid || cve.String != "CVE-2024-9999" {
		t.Errorf("cve_id = %v, want CVE-2024-9999 — first-sighting batch insert dropped the CVE", cve)
	}
	if !cvss.Valid || cvss.Float64 != 9.8 {
		t.Errorf("cvss_score = %v, want 9.8 — first-sighting batch insert dropped the CVSS score", cvss)
	}
	if !vec.Valid || vec.String == "" {
		t.Errorf("cvss_vector = %v, want non-empty — first-sighting batch insert dropped the CVSS vector", vec)
	}
	if len(cwes) != 2 || cwes[0] != "CWE-79" {
		t.Errorf("cwe_ids = %v, want [CWE-79 CWE-89]", cwes)
	}
	if len(owasps) != 1 || owasps[0] != "A03:2021" {
		t.Errorf("owasp_ids = %v, want [A03:2021]", owasps)
	}

	// Re-ingest with a re-scored CVSS refreshes the stored value (ON CONFLICT).
	if err := repo.CreateBatch(ctx, []*vulnerability.Finding{mkFinding(t, 5.0)}); err != nil {
		t.Fatalf("re-ingest: %v", err)
	}
	_, cvss2, _, _, _ := read()
	if !cvss2.Valid || cvss2.Float64 != 5.0 {
		t.Errorf("cvss_score after re-ingest = %v, want 5.0 — ON CONFLICT must refresh classification", cvss2)
	}
}
