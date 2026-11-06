package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cvecorpus"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/softwarematch"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// A tenant report naming a CVE creates at most an identity stub in the shared
// catalog: none of the report's text reaches what other tenants read, and the
// public corpus fills the row (docs/architecture/global-catalog-trust.md).

type cveCatalogRow struct {
	title, severity, origin string
	desc, vector            sql.NullString
	cvss                    sql.NullFloat64
	refs, affected          string
	fixed, aliases          string
	published               sql.NullTime
}

func readCatalogRow(ctx context.Context, t *testing.T, db *sql.DB, cve string) cveCatalogRow {
	t.Helper()
	var r cveCatalogRow
	if err := db.QueryRowContext(ctx, `
		SELECT title, severity, origin, description, cvss_vector, cvss_score, reference_urls::text,
			affected_versions::text, COALESCE(fixed_versions, '{}')::text, COALESCE(aliases, '{}')::text, published_at
		FROM vulnerabilities WHERE cve_id = $1 AND tenant_id IS NULL`, cve).
		Scan(&r.title, &r.severity, &r.origin, &r.desc, &r.vector, &r.cvss, &r.refs, &r.affected, &r.fixed, &r.aliases, &r.published); err != nil {
		t.Fatal(err)
	}
	return r
}

func craftedReport(t *testing.T, cve string) *vulnerability.Vulnerability {
	t.Helper()
	v := sensorReportedVuln(t, cve)
	v.UpdateDescription("tenant A internal host db01.corp.example.com is affected")
	v.AddReference(vulnerability.NewReference("scanner", "https://attacker.example.com/advisory"))
	v.SetFixedVersions([]string{"9.9.9-acme"})
	v.SetPublishedAt(time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC))
	return v
}

func cleanupCVE(t *testing.T, db *sql.DB, cves ...string) {
	t.Cleanup(func() {
		for _, c := range cves {
			for _, q := range []string{
				`DELETE FROM findings WHERE cve_id = $1`,
				`DELETE FROM vulnerabilities WHERE cve_id = $1`,
				`DELETE FROM cve_records WHERE cve_id = $1`,
				`DELETE FROM kev_catalog WHERE cve_id = $1`,
			} {
				_, _ = db.ExecContext(context.Background(), q, c)
			}
		}
	})
}

func assertStub(t *testing.T, r cveCatalogRow, cve string) {
	t.Helper()
	if r.origin != "report" || r.title != cve || r.desc.Valid || r.cvss.Valid || r.vector.Valid ||
		r.refs != "[]" || r.affected != "[]" || r.fixed != "{}" || r.aliases != "{}" || r.published.Valid || r.severity != "unknown" {
		t.Errorf("tenant report text reached the shared catalog row: %+v", r)
	}
}

func TestCatalogStub_TenantReportCreatesIdentityStubOnly(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	cve := uniqueCVE()
	cleanupCVE(t, db, cve)

	if err := NewVulnerabilityRepository(&DB{DB: db}).UpsertBatchByCVE(ctx, []*vulnerability.Vulnerability{craftedReport(t, cve)}); err != nil {
		t.Fatal(err)
	}
	assertStub(t, readCatalogRow(ctx, t, db, cve), cve)
}

func TestCatalogStub_ReportOfACorpusCVETakesTheCorpusContent(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	cve := uniqueCVE()
	cleanupCVE(t, db, cve)
	if _, err := db.ExecContext(ctx, `INSERT INTO cve_records (cve_id, description, cvss_score, cvss_vector, cvss_version, severity, published_at)
		VALUES ($1, 'feed description', 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', '3.1', 'critical', '2020-02-02')`, cve); err != nil {
		t.Fatal(err)
	}

	if err := NewVulnerabilityRepository(&DB{DB: db}).UpsertBatchByCVE(ctx, []*vulnerability.Vulnerability{craftedReport(t, cve)}); err != nil {
		t.Fatal(err)
	}
	r := readCatalogRow(ctx, t, db, cve)
	if r.origin != "nvd" || r.title != cve || r.desc.String != "feed description" || r.cvss.Float64 != 9.8 ||
		r.severity != "critical" || r.refs != "[]" || r.fixed != "{}" || r.published.Time.Year() != 2020 {
		t.Errorf("row not built from the corpus alone: %+v", r)
	}
}

func TestCatalogStub_CorpusImportFillsAStub(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	cve, other := uniqueCVE(), uniqueCVE()
	cleanupCVE(t, db, cve, other)
	vulns := NewVulnerabilityRepository(&DB{DB: db})
	if err := vulns.UpsertBatchByCVE(ctx, []*vulnerability.Vulnerability{craftedReport(t, cve), craftedReport(t, other)}); err != nil {
		t.Fatal(err)
	}
	// The corpus already has a record for cve (so the page updates it) and
	// learns its content now; other is not in this page.
	if _, err := db.ExecContext(ctx, `INSERT INTO cve_records (cve_id) VALUES ($1)`, cve); err != nil {
		t.Fatal(err)
	}
	score := 7.5
	pub := time.Date(2021, 3, 3, 0, 0, 0, 0, time.UTC)
	if _, err := NewCVECorpusRepository(&DB{DB: db}).ApplyPage(ctx, []cvecorpus.CVE{{
		ID: cve, Description: "feed description", CVSSScore: &score, CVSSVersion: "3.1",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", Severity: "high", Published: &pub, TooManyRanges: true,
	}}); err != nil {
		t.Fatal(err)
	}
	r := readCatalogRow(ctx, t, db, cve)
	if r.origin != "nvd" || r.desc.String != "feed description" || r.cvss.Float64 != 7.5 || r.severity != "high" || !r.published.Valid {
		t.Errorf("corpus import did not fill the stub: %+v", r)
	}
	assertStub(t, readCatalogRow(ctx, t, db, other), other)
}

func TestCatalogStub_MatcherDefinitionFillsAStub(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	cve := uniqueCVE()
	cleanupCVE(t, db, cve)
	if err := NewVulnerabilityRepository(&DB{DB: db}).UpsertBatchByCVE(ctx, []*vulnerability.Vulnerability{craftedReport(t, cve)}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO cve_records (cve_id, description, severity) VALUES ($1, 'feed description', 'medium')`, cve); err != nil {
		t.Fatal(err)
	}
	ids, err := NewSoftwareMatchRepository(&DB{DB: db}).EnsureDefinitions(ctx, []softwarematch.CVEInfo{{ID: cve}})
	if err != nil || ids[cve].IsZero() {
		t.Fatalf("EnsureDefinitions = %v %v", ids, err)
	}
	if r := readCatalogRow(ctx, t, db, cve); r.origin != "nvd" || r.desc.String != "feed description" || r.severity != "medium" {
		t.Errorf("the corpus never replaced the report stub: %+v", r)
	}
}

// The catalog API shows feed-backed rows to everyone and a stub only to an
// organization whose own findings link to it: the existence of a stub would
// otherwise tell every tenant that someone reported the CVE.
func TestCatalogView_HidesAnotherTenantsStub(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	stub, fed := uniqueCVE(), uniqueCVE()
	cleanupCVE(t, db, stub, fed)
	if _, err := db.ExecContext(ctx, `INSERT INTO cve_records (cve_id, description) VALUES ($1, 'feed description')`, fed); err != nil {
		t.Fatal(err)
	}
	vulns := NewVulnerabilityRepository(&DB{DB: db})
	reported := craftedReport(t, stub)
	if err := vulns.UpsertBatchByCVE(ctx, []*vulnerability.Vulnerability{reported, craftedReport(t, fed)}); err != nil {
		t.Fatal(err)
	}

	tA, tB := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	aA := seedTestAsset(ctx, t, db, tA)
	if _, err := db.ExecContext(ctx, `
		INSERT INTO findings (tenant_id, asset_id, vulnerability_id, cve_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1, $2, $3, $4, 'sca', 'trivy', 'm', 'high', $5, 'new')`,
		tA.String(), aA.String(), reported.ID().String(), stub, "fp-"+shared.NewID().String()); err != nil {
		t.Fatal(err)
	}

	visible := func(viewer *shared.ID) map[string]bool {
		t.Helper()
		f := vulnerability.NewVulnerabilityFilter().WithCVEIDs(stub, fed)
		f.CatalogView = true
		f.ViewerTenantID = viewer
		res, err := vulns.List(ctx, f, vulnerability.NewVulnerabilityListOptions(), pagination.New(1, 10))
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, v := range res.Data {
			out[v.CVEID()] = true
		}
		if int(res.Total) != len(out) {
			t.Errorf("count %d disagrees with rows %v", res.Total, out)
		}
		return out
	}

	if got := visible(&tB); got[stub] || !got[fed] {
		t.Errorf("tenant B sees %v: want only the feed-backed CVE", got)
	}
	if got := visible(nil); got[stub] || !got[fed] {
		t.Errorf("no organization sees %v: want only the feed-backed CVE", got)
	}
	if got := visible(&tA); !got[stub] || !got[fed] {
		t.Errorf("tenant A sees %v: want its own stub and the feed-backed CVE", got)
	}

	// By id, as GET /vulnerabilities/{id} reads it.
	f := vulnerability.NewVulnerabilityFilter()
	f.CatalogView, f.ViewerTenantID, f.IDs = true, &tB, []shared.ID{reported.ID()}
	if res, err := vulns.List(ctx, f, vulnerability.NewVulnerabilityListOptions(), pagination.New(1, 1)); err != nil || len(res.Data) != 0 {
		t.Errorf("tenant B reads tenant A's stub by id: %d rows, %v", len(res.Data), err)
	}
}
