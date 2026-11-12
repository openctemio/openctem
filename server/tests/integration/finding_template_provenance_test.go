package integration

// Template provenance at ingest (research/18 O6, sensor#134): a nuclei
// finding's template_digest and template_path, and the report's template
// release, are kept on the finding as its last sighting's baseline; a
// sighting without a digest keeps the baseline, one with a new digest
// re-baselines it; hostile values are dropped; another tenant is never
// touched. The coverage-side helpers are checked against the same rows.

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/internal/app/ingest"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

const (
	provDigestA   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	provDigestB   = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	provReleaseV1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
)

// bareHex is the lowercase hex of a "sha256:<hex>" digest: CTIS 2.0 carries
// content hashes without the algorithm prefix.
func bareHex(d string) string { return strings.TrimPrefix(d, "sha256:") }

// provenanceReport is a nuclei report whose finding names a rule (rule_ref)
// with the template digest and path, and whose tool lists the template
// release (tool.content).
func provenanceReport(host, digest, path, release string) *ctis.Report {
	tool := &ctis.Tool{Name: "nuclei", Version: "3.11.1"}
	if release != "" {
		tool.Content = []ctis.ToolContent{{Name: "nuclei-templates", Version: "v10.4.9", SHA256: bareHex(release)}}
	}
	rep := &ctis.Report{Version: ctis.SchemaVersion, Tool: tool,
		Metadata: ctis.ReportMetadata{ID: ctis.NewReportID(), GeneratedAt: time.Now().UTC()},
		Assets:   []ctis.Asset{{ID: "h", Type: ctis.AssetTypeDomainName, Value: host}},
		Findings: []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "Exposed admin panel", Severity: ctis.SeverityHigh,
			RuleID: "exposed-admin-panel", AssetRef: "h"}}}
	if digest != "" || path != "" {
		rep.Rules = []ctis.Rule{{ID: "r1", RuleID: "exposed-admin-panel", ContentSHA256: bareHex(digest), ContentPath: path}}
		rep.Findings[0].RuleRef = "r1"
	}
	return rep
}

type provRow struct{ digest, path, version, release sql.NullString }

func provenanceOf(t *testing.T, r *v2Rig, tenant shared.ID) provRow {
	t.Helper()
	var p provRow
	if err := r.db.QueryRow(`SELECT template_digest, template_path, templates_version, templates_digest
		FROM findings WHERE tenant_id = $1`, tenant.String()).Scan(&p.digest, &p.path, &p.version, &p.release); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFindingTemplateProvenance_KeptAndRebaselined(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	db := &postgres.DB{DB: r.db}
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	ingestAs := func(tn v2Tenant, rep *ctis.Report) {
		t.Helper()
		tid := tn.tenant
		agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
		if _, err := svc.Ingest(context.Background(), agt, ingest.Input{Report: rep}); err != nil {
			t.Fatal(err)
		}
	}
	// hostileAs sends a report a producer could forge: ingest may refuse it
	// (the document is invalid) or store it with the hostile value dropped;
	// either way the baseline must not change.
	hostileAs := func(tn v2Tenant, rep *ctis.Report) {
		t.Helper()
		tid := tn.tenant
		agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
		_, _ = svc.Ingest(context.Background(), agt, ingest.Input{Report: rep})
	}
	tn := r.newTenant("nuclei")
	other := r.newTenant("nuclei")
	host := "prov-" + tn.tenant.String()[:8] + ".example.com"

	// First sighting: digest, path and release kept.
	ingestAs(tn, provenanceReport(host, provDigestA, "http/exposures/admin.yaml", provReleaseV1))
	p := provenanceOf(t, r, tn.tenant)
	if p.digest.String != provDigestA || p.path.String != "http/exposures/admin.yaml" || p.version.String != "v10.4.9" || p.release.String != provReleaseV1 {
		t.Fatalf("first sighting stored %+v", p)
	}

	// A sighting without a digest (an older sensor) keeps the baseline.
	ingestAs(tn, provenanceReport(host, "", "", ""))
	if p := provenanceOf(t, r, tn.tenant); p.digest.String != provDigestA {
		t.Fatalf("a sighting without a digest changed the baseline: %+v", p)
	}

	// Hostile values are dropped, the baseline stays.
	hostileAs(tn, provenanceReport(host, "sha256:ZZZ'; DROP TABLE findings; --", "../../etc/passwd", "md5:nope"))
	if p := provenanceOf(t, r, tn.tenant); p.digest.String != provDigestA || p.path.String != "http/exposures/admin.yaml" {
		t.Fatalf("hostile values reached the row: %+v", p)
	}

	// A new digest re-baselines; a hostile path is dropped, not stored.
	ingestAs(tn, provenanceReport(host, provDigestB, "/abs/path.yaml", ""))
	p = provenanceOf(t, r, tn.tenant)
	if p.digest.String != provDigestB || p.path.Valid || p.release.Valid {
		t.Fatalf("re-baseline stored %+v", p)
	}

	// Another tenant's ingest of the same host never touches this tenant.
	ingestAs(other, provenanceReport(host, provDigestA, "", provReleaseV1))
	if p := provenanceOf(t, r, tn.tenant); p.digest.String != provDigestB {
		t.Fatalf("another tenant's sighting re-baselined this tenant: %+v", p)
	}

	// The coverage helpers on the same rows: a run with another (or no)
	// release drifts the finding of `other` (baseline release V1).
	repo := postgres.NewFindingRepository(db)
	var id string
	if err := r.db.QueryRow(`SELECT id FROM findings WHERE tenant_id = $1`, other.tenant.String()).Scan(&id); err != nil {
		t.Fatal(err)
	}
	fid := shared.MustIDFromString(id)
	for run, wantDrift := range map[string]bool{provReleaseV1: false, provDigestB: true, "": true} {
		got, err := repo.TemplateDriftedFindings(context.Background(), other.tenant, []shared.ID{fid}, run)
		if err != nil || (len(got) == 1) != wantDrift {
			t.Errorf("run release %q: drifted %v err %v, want drift=%v", run, got, err, wantDrift)
		}
	}
	// Tenant-scoped: asked as another tenant, nothing.
	if got, _ := repo.TemplateDriftedFindings(context.Background(), tn.tenant, []shared.ID{fid}, ""); len(got) != 0 {
		t.Errorf("cross-tenant drift lookup returned %v", got)
	}
	if got, _ := repo.MarkCoverageNotObserved(context.Background(), tn.tenant, []shared.ID{fid}); len(got) != 0 {
		t.Errorf("cross-tenant stale marked %v", got)
	}
	marked, err := repo.MarkCoverageNotObserved(context.Background(), other.tenant, []shared.ID{fid})
	if err != nil || len(marked) != 1 {
		t.Fatalf("mark stale: %v %v", marked, err)
	}
	var status, observation string
	_ = r.db.QueryRow(`SELECT status, observation_state FROM findings WHERE id = $1`, id).Scan(&status, &observation)
	if observation != "stale" || status == "resolved" {
		t.Errorf("status = %s, observation = %s; want an open, stale finding", status, observation)
	}
}
