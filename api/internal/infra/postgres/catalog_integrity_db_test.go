package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/component"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// The vulnerabilities, components and licenses catalogs are shared by every
// tenant. A tenant's sensor (or SBOM upload) must not be able to change what
// other tenants see there: see docs/architecture/global-catalog-trust.md.

func catalogTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
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

// uniqueCVE returns a syntactically valid CVE id nobody else uses.
func uniqueCVE() string {
	return fmt.Sprintf("CVE-2099-%d", 10000+time.Now().UnixNano()%89999999)
}

// sensorReportedVuln is what a hostile (or simply wrong) sensor reports.
func sensorReportedVuln(t *testing.T, cve string) *vulnerability.Vulnerability {
	t.Helper()
	v, err := vulnerability.NewVulnerability(cve, "attacker title", vulnerability.SeverityLow)
	if err != nil {
		t.Fatal(err)
	}
	v.UpdateDescription("attacker description")
	v.UpdateCVSS(0.1, "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N")
	v.UpdateEPSS(0.99, 99.9)
	v.SetExploitAvailable(true)
	v.SetExploitMaturity(vulnerability.ExploitMaturityWeaponized)
	kev := vulnerability.NewCISAKEV(time.Now().UTC(), time.Now().UTC().Add(24*time.Hour), "Known", "attacker")
	v.SetCISAKEV(&kev)
	return v
}

func TestVulnCatalog_TenantIngestCannotChangeAnExistingCVE(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	cve := uniqueCVE()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM vulnerabilities WHERE cve_id = $1`, cve)
	})

	// The catalog already knows this CVE: not exploited, not in KEV.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO vulnerabilities (cve_id, title, severity, cvss_score, exploit_available, exploit_maturity)
		VALUES ($1, 'real title', 'critical', 9.8, false, 'none')`, cve); err != nil {
		t.Fatal(err)
	}

	repo := NewVulnerabilityRepository(&DB{DB: db})
	if err := repo.UpsertBatchByCVE(ctx, []*vulnerability.Vulnerability{sensorReportedVuln(t, cve)}); err != nil {
		t.Fatal(err)
	}

	var title, severity, maturity string
	var desc sql.NullString
	var cvss, epss sql.NullFloat64
	var exploit bool
	var kev sql.NullTime
	if err := db.QueryRowContext(ctx, `
		SELECT title, severity, description, cvss_score, epss_score, exploit_available, exploit_maturity, cisa_kev_date_added
		FROM vulnerabilities WHERE cve_id = $1`, cve).Scan(&title, &severity, &desc, &cvss, &epss, &exploit, &maturity, &kev); err != nil {
		t.Fatal(err)
	}
	if exploit || maturity != "none" {
		t.Errorf("a tenant flipped the shared exploit flags: exploit_available=%v maturity=%s", exploit, maturity)
	}
	if kev.Valid || epss.Valid {
		t.Errorf("a tenant set shared threat intel: kev=%v epss=%v", kev, epss)
	}
	if title != "real title" || severity != "critical" || cvss.Float64 != 9.8 || desc.Valid {
		t.Errorf("a tenant changed shared descriptive fields: title=%q sev=%s cvss=%v desc=%v", title, severity, cvss, desc)
	}
}

func TestVulnCatalog_NewCVEFromTenantGetsRiskSignalsOnlyFromThreatIntel(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	cve := uniqueCVE()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM vulnerabilities WHERE cve_id = $1`, cve)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM epss_scores WHERE cve_id = $1`, cve)
	})
	// Trusted feed: EPSS knows this CVE, KEV does not.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO epss_scores (cve_id, epss_score, percentile, score_date) VALUES ($1, 0.0123, 0.45, CURRENT_DATE)`, cve); err != nil {
		t.Fatal(err)
	}

	repo := NewVulnerabilityRepository(&DB{DB: db})
	if err := repo.UpsertBatchByCVE(ctx, []*vulnerability.Vulnerability{sensorReportedVuln(t, cve)}); err != nil {
		t.Fatal(err)
	}

	var exploit bool
	var maturity string
	var epss sql.NullFloat64
	var kev sql.NullTime
	if err := db.QueryRowContext(ctx, `
		SELECT exploit_available, exploit_maturity, epss_score, cisa_kev_date_added FROM vulnerabilities WHERE cve_id = $1`, cve).
		Scan(&exploit, &maturity, &epss, &kev); err != nil {
		t.Fatal(err)
	}
	if exploit || maturity != "none" || kev.Valid {
		t.Errorf("tenant-reported exploit/KEV reached the shared catalog: exploit=%v maturity=%s kev=%v", exploit, maturity, kev)
	}
	if !epss.Valid || epss.Float64 != 0.0123 {
		t.Errorf("EPSS must come from the EPSS feed (0.0123), got %v", epss)
	}
}

func TestComponentCatalog_TenantCannotOverwriteSharedFields(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	repo := NewComponentRepository(&DB{DB: db})

	name := "catalog-test-" + shared.NewID().String()
	first, err := component.NewComponent(name, "1.0.0", component.EcosystemNPM)
	if err != nil {
		t.Fatal(err)
	}
	first.UpdateDescription("real description")
	first.UpdateHomepage("https://real.example")
	id, err := repo.Upsert(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM components WHERE id = $1`, id.String())
	})

	evil, _ := component.NewComponent(name, "1.0.0", component.EcosystemNPM)
	evil.UpdateDescription("attacker description")
	evil.UpdateHomepage("https://evil.example")
	if _, err := repo.Upsert(ctx, evil); err != nil {
		t.Fatal(err)
	}

	var desc, home sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT description, homepage FROM components WHERE id = $1`, id.String()).Scan(&desc, &home); err != nil {
		t.Fatal(err)
	}
	if desc.String != "real description" || home.String != "https://real.example" {
		t.Errorf("a later upsert overwrote the shared component: description=%q homepage=%q", desc.String, home.String)
	}
}

func TestLicenses_AreTenantLocal(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	repo := NewComponentRepository(&DB{DB: db})
	tA, tB := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	aA, aB := seedTestAsset(ctx, t, db, tA), seedTestAsset(ctx, t, db, tB)

	c, _ := component.NewComponent("lic-test-"+shared.NewID().String(), "1.0.0", component.EcosystemNPM)
	id, err := repo.Upsert(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM components WHERE id = $1`, id.String())
	})

	// Tenant A's sensor declares AGPL; tenant B's declares MIT.
	for _, p := range []struct {
		tenant, asset shared.ID
		license       string
	}{{tA, aA, "AGPL-3.0-only"}, {tB, aB, "MIT"}} {
		valid, err := repo.EnsureLicenses(ctx, []string{p.license, "not a license!"})
		if err != nil || len(valid) != 1 {
			t.Fatalf("EnsureLicenses = %v %v", valid, err)
		}
		d, _ := component.NewAssetDependency(p.tenant, p.asset, id, "package.json", component.DependencyTypeDirect)
		d.SetLicense(valid[0])
		if err := repo.LinkAsset(ctx, d); err != nil {
			t.Fatal(err)
		}
	}

	licensesOf := func(tenant shared.ID) map[string]bool {
		stats, err := repo.GetLicenseStats(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, s := range stats {
			out[s.LicenseID] = true
		}
		return out
	}
	if b := licensesOf(tB); b["AGPL-3.0-only"] || !b["MIT"] {
		t.Errorf("tenant B's license report = %v; want only MIT", b)
	}
	if a := licensesOf(tA); !a["AGPL-3.0-only"] || a["MIT"] {
		t.Errorf("tenant A's license report = %v; want only AGPL-3.0-only", a)
	}

	// A re-scan that declares no license keeps the recorded one.
	d, _ := component.NewAssetDependency(tB, aB, id, "package.json", component.DependencyTypeDirect)
	if err := repo.LinkAsset(ctx, d); err != nil {
		t.Fatal(err)
	}
	if b := licensesOf(tB); !b["MIT"] {
		t.Errorf("license lost on re-scan: %v", b)
	}
}

func TestThreatIntelPropagation_SetsCatalogRiskSignals(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	cve := uniqueCVE()
	t.Cleanup(func() {
		for _, q := range []string{`DELETE FROM vulnerabilities WHERE cve_id = $1`, `DELETE FROM epss_scores WHERE cve_id = $1`, `DELETE FROM kev_catalog WHERE cve_id = $1`} {
			_, _ = db.ExecContext(context.Background(), q, cve)
		}
	})
	if err := NewVulnerabilityRepository(&DB{DB: db}).UpsertBatchByCVE(ctx, []*vulnerability.Vulnerability{sensorReportedVuln(t, cve)}); err != nil {
		t.Fatal(err)
	}
	// The feeds learn about the CVE after it entered the catalog.
	if _, err := db.ExecContext(ctx, `INSERT INTO epss_scores (cve_id, epss_score, percentile, score_date) VALUES ($1, 0.5, 0.9, CURRENT_DATE)`, cve); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO kev_catalog (cve_id, vulnerability_name, date_added, known_ransomware_campaign_use) VALUES ($1, 'kev name', CURRENT_DATE, 'Known')`, cve); err != nil {
		t.Fatal(err)
	}
	n, err := NewThreatIntelRepository(&DB{DB: db}).PropagateToVulnerabilityCatalog(ctx)
	if err != nil || n < 1 {
		t.Fatalf("propagate = %d %v", n, err)
	}
	var exploit bool
	var epss sql.NullFloat64
	var kev sql.NullTime
	var ransomware sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT exploit_available, epss_score, cisa_kev_date_added, cisa_kev_ransomware_use FROM vulnerabilities WHERE cve_id = $1`, cve).
		Scan(&exploit, &epss, &kev, &ransomware); err != nil {
		t.Fatal(err)
	}
	if !exploit || epss.Float64 != 0.5 || !kev.Valid || ransomware.String != "Known" {
		t.Errorf("catalog not updated from the feeds: exploit=%v epss=%v kev=%v ransomware=%v", exploit, epss, kev, ransomware)
	}
}

// A CVE that CISA removed from KEV: the sync prunes kev_catalog, then the
// propagation must clear the catalog's KEV columns and exploit_available.
// Before the fix the propagation only ever set them.
func TestThreatIntelPropagation_ClearsCVEThatLeftKEV(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	cve, other := uniqueCVE(), uniqueCVE()
	t.Cleanup(func() {
		for _, c := range []string{cve, other} {
			for _, q := range []string{`DELETE FROM vulnerabilities WHERE cve_id = $1`, `DELETE FROM kev_catalog WHERE cve_id = $1`} {
				_, _ = db.ExecContext(context.Background(), q, c)
			}
		}
	})
	vulns := NewVulnerabilityRepository(&DB{DB: db})
	if err := vulns.UpsertBatchByCVE(ctx, []*vulnerability.Vulnerability{sensorReportedVuln(t, cve), sensorReportedVuln(t, other)}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{cve, other} {
		if _, err := db.ExecContext(ctx, `INSERT INTO kev_catalog (cve_id, vulnerability_name, date_added, due_date, known_ransomware_campaign_use) VALUES ($1, 'kev name', CURRENT_DATE, CURRENT_DATE, 'Known')`, c); err != nil {
			t.Fatal(err)
		}
	}
	ti := NewThreatIntelRepository(&DB{DB: db})
	if _, err := ti.PropagateToVulnerabilityCatalog(ctx); err != nil {
		t.Fatal(err)
	}

	// CISA drops cve; the next feed holds every other entry.
	var keep []string
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(array_agg(cve_id), '{}') FROM kev_catalog WHERE cve_id <> $1`, cve).
		Scan(pq.Array(&keep)); err != nil {
		t.Fatal(err)
	}
	n, err := ti.KEV().PruneNotIn(ctx, keep)
	if err != nil || n != 1 {
		t.Fatalf("PruneNotIn = %d %v, want 1 removed", n, err)
	}
	if _, err := ti.PropagateToVulnerabilityCatalog(ctx); err != nil {
		t.Fatal(err)
	}

	read := func(c string) (exploit bool, added, due sql.NullTime, ransomware sql.NullString) {
		if err := db.QueryRowContext(ctx, `SELECT exploit_available, cisa_kev_date_added, cisa_kev_due_date, cisa_kev_ransomware_use FROM vulnerabilities WHERE cve_id = $1`, c).
			Scan(&exploit, &added, &due, &ransomware); err != nil {
			t.Fatal(err)
		}
		return
	}
	if exploit, added, due, rw := read(cve); exploit || added.Valid || due.Valid || rw.Valid {
		t.Errorf("CVE that left KEV still flagged: exploit=%v added=%v due=%v ransomware=%v", exploit, added, due, rw)
	}
	if exploit, added, _, _ := read(other); !exploit || !added.Valid {
		t.Errorf("CVE still in KEV lost its flags: exploit=%v added=%v", exploit, added)
	}
}

// A CVE first reported by tenant A with a low severity must still show (and
// filter) as critical for tenant B whose own finding is critical.
func TestActiveCVEs_TenantViewUsesOwnObservation(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	cve := uniqueCVE()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM vulnerabilities WHERE cve_id = $1`, cve)
	})

	vulns := NewVulnerabilityRepository(&DB{DB: db})
	poisoned := sensorReportedVuln(t, cve) // severity low, CVSS 0.1, exploit claimed
	if err := vulns.UpsertBatchByCVE(ctx, []*vulnerability.Vulnerability{poisoned}); err != nil {
		t.Fatal(err)
	}

	tB := seedTestTenant(ctx, t, db)
	aB := seedTestAsset(ctx, t, db, tB)
	if _, err := db.ExecContext(ctx, `
		INSERT INTO findings (tenant_id, asset_id, vulnerability_id, cve_id, source, tool_name, message, severity, fingerprint, cvss_score, status)
		VALUES ($1, $2, $3, $4, 'sca', 'trivy', 'm', 'critical', $5, 9.8, 'new')`,
		tB.String(), aB.String(), poisoned.ID().String(), cve, "fp-"+shared.NewID().String()); err != nil {
		t.Fatal(err)
	}

	findings := NewFindingRepository(&DB{DB: db})
	res, err := findings.ListActiveCVEsByTenant(ctx, tB, vulnerability.ActiveCVEFilter{SeverityIn: []string{"critical"}}, pagination.New(1, 10))
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 1 || len(res.Data) != 1 {
		t.Fatalf("tenant B's critical CVE is hidden by tenant A's report: total=%d", res.Total)
	}
	got := res.Data[0]
	if got.Severity != "critical" || got.CVSSScore == nil || *got.CVSSScore != 9.8 || got.ExploitAvailable {
		t.Errorf("tenant B sees %s cvss=%v exploit=%v; want its own critical/9.8 and no exploit claim from tenant A",
			got.Severity, got.CVSSScore, got.ExploitAvailable)
	}
	stats, err := findings.GetActiveCVEStats(ctx, tB, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if stats.ExploitAvailableCount != 0 {
		t.Errorf("stats count tenant A's exploit claim: %d", stats.ExploitAvailableCount)
	}
}
