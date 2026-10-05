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
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	provDigestA   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	provDigestB   = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	provReleaseV1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
)

func provenanceReport(host string, props ctis.Properties, release string) *ctis.Report {
	tool := &ctis.Tool{Name: "nuclei", Version: "3.11.1"}
	if release != "" {
		tool.Properties = ctis.Properties{"content": []any{
			map[string]any{"name": "nuclei-templates", "version": "v10.4.9", "digest": release, "managed": true},
		}}
	}
	return &ctis.Report{Version: "1.0", Tool: tool,
		Metadata: ctis.ReportMetadata{ID: shared.NewID().String(), Timestamp: time.Now().UTC()},
		Assets:   []ctis.Asset{{ID: "h", Type: ctis.AssetTypeDomain, Value: host}},
		Findings: []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "Exposed admin panel", Severity: ctis.SeverityHigh,
			RuleID: "exposed-admin-panel", AssetRef: "h", Properties: props}}}
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
	tn := r.newTenant("nuclei")
	other := r.newTenant("nuclei")
	host := "prov-" + tn.tenant.String()[:8] + ".example.com"

	// First sighting: digest, path and release kept.
	ingestAs(tn, provenanceReport(host, ctis.Properties{"template_digest": provDigestA, "template_path": "http/exposures/admin.yaml"}, provReleaseV1))
	p := provenanceOf(t, r, tn.tenant)
	if p.digest.String != provDigestA || p.path.String != "http/exposures/admin.yaml" || p.version.String != "v10.4.9" || p.release.String != provReleaseV1 {
		t.Fatalf("first sighting stored %+v", p)
	}

	// A sighting without a digest (an older sensor) keeps the baseline.
	ingestAs(tn, provenanceReport(host, nil, ""))
	if p := provenanceOf(t, r, tn.tenant); p.digest.String != provDigestA {
		t.Fatalf("a sighting without a digest changed the baseline: %+v", p)
	}

	// Hostile values are dropped, the baseline stays.
	ingestAs(tn, provenanceReport(host, ctis.Properties{"template_digest": "sha256:ZZZ'; DROP TABLE findings; --", "template_path": "../../etc/passwd"}, "md5:nope"))
	if p := provenanceOf(t, r, tn.tenant); p.digest.String != provDigestA || p.path.String != "http/exposures/admin.yaml" {
		t.Fatalf("hostile values reached the row: %+v", p)
	}

	// A new digest re-baselines; a hostile path is dropped, not stored.
	ingestAs(tn, provenanceReport(host, ctis.Properties{"template_digest": provDigestB, "template_path": "/abs/path.yaml"}, ""))
	p = provenanceOf(t, r, tn.tenant)
	if p.digest.String != provDigestB || p.path.Valid || p.release.Valid {
		t.Fatalf("re-baseline stored %+v", p)
	}

	// Another tenant's ingest of the same host never touches this tenant.
	ingestAs(other, provenanceReport(host, ctis.Properties{"template_digest": provDigestA}, provReleaseV1))
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
		t.Errorf("cross-tenant not_observed marked %v", got)
	}
	marked, err := repo.MarkCoverageNotObserved(context.Background(), other.tenant, []shared.ID{fid})
	if err != nil || len(marked) != 1 {
		t.Fatalf("mark not_observed: %v %v", marked, err)
	}
	var status string
	_ = r.db.QueryRow(`SELECT status FROM findings WHERE id = $1`, id).Scan(&status)
	if status != "not_observed" {
		t.Errorf("status = %s, want not_observed", status)
	}
}
