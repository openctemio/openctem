package integration

// Rule provenance at ingest (docs/architecture/rule-sources.md): a finding
// records whether the platform's rules or the organization's own found it,
// and for the organization's, which scanner template (by the template's
// digest, or by the rule id the sensor marked as the organization's). Only
// the finding's own tenant's templates are ever matched.

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func seedScannerTemplate(t *testing.T, db *sql.DB, tenant shared.ID, name, typ, hash, metadata string) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.Exec(`INSERT INTO scanner_templates (id, tenant_id, name, template_type, version, content, content_hash, metadata)
		VALUES ($1, $2, $3, $4, '1.2.0', 'x', $5, $6::jsonb)`, id.String(), tenant.String(), name, typ, hash, metadata); err != nil {
		t.Fatalf("seed template: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM scanner_templates WHERE id = $1`, id.String()) })
	return id
}

type ruleProvRow struct{ source, templateID, version sql.NullString }

func ruleProvenanceOf(t *testing.T, db *sql.DB, tenant shared.ID, ruleID string) (string, ruleProvRow) {
	t.Helper()
	var id string
	var p ruleProvRow
	if err := db.QueryRow(`SELECT id, rule_source, custom_template_id::text, custom_template_version
		FROM findings WHERE tenant_id = $1 AND rule_id = $2`, tenant.String(), ruleID).Scan(&id, &p.source, &p.templateID, &p.version); err != nil {
		t.Fatalf("finding %s: %v", ruleID, err)
	}
	return id, p
}

func TestFindingRuleProvenance(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	db := &postgres.DB{DB: r.db}
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	tn := r.newTenant("nuclei")
	other := r.newTenant("nuclei")
	host := "rules-" + tn.tenant.String()[:8] + ".example.com"
	ingestAs := func(rep *ctis.Report) {
		t.Helper()
		tid := tn.tenant
		agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
		if _, err := svc.Ingest(context.Background(), agt, ingest.Input{Report: rep}); err != nil {
			t.Fatal(err)
		}
	}
	finding := func(ruleID string, props ctis.Properties) *ctis.Report {
		rep := provenanceReport(host, props, "")
		rep.Findings[0].RuleID = ruleID
		rep.Findings[0].Title = "finding " + ruleID
		return rep
	}

	hashA := strings.Repeat("a", 64)
	hashOther := strings.Repeat("b", 64)
	nucleiTpl := seedScannerTemplate(t, r.db, tn.tenant, "login-panel.yaml", "nuclei", hashA, `{"id":"login-panel"}`)
	semgrepTpl := seedScannerTemplate(t, r.db, tn.tenant, "python-rules.yaml", "semgrep", strings.Repeat("c", 64), `{"rule_ids":["weak-hash","hardcoded-password"]}`)
	// Another tenant's template whose content matches a platform template.
	seedScannerTemplate(t, r.db, other.tenant, "copied.yaml", "nuclei", hashOther, `{"id":"exposed-admin-panel"}`)

	// The organization's nuclei template (marked by the sensor): its
	// template and version are linked by the digest.
	ingestAs(finding("tenant:login-panel", ctis.Properties{"template_digest": "sha256:" + hashA, "rule_source": "tenant"}))
	_, p := ruleProvenanceOf(t, r.db, tn.tenant, "tenant:login-panel")
	if p.source.String != "tenant" || p.templateID.String != nucleiTpl.String() || p.version.String != "1.2.0" {
		t.Fatalf("organization nuclei finding: %+v", p)
	}

	// A platform template: platform, no template, even though another
	// tenant has a template with that exact content.
	ingestAs(finding("exposed-admin-panel", ctis.Properties{"template_digest": "sha256:" + hashOther}))
	_, p = ruleProvenanceOf(t, r.db, tn.tenant, "exposed-admin-panel")
	if p.source.String != "platform" || p.templateID.Valid {
		t.Fatalf("platform finding linked another tenant's template: %+v", p)
	}

	// An organization rule without a digest (semgrep): the template that
	// defines the rule id.
	ingestAs(finding("tenant:weak-hash", nil))
	semgrepFinding, p := ruleProvenanceOf(t, r.db, tn.tenant, "tenant:weak-hash")
	if p.source.String != "tenant" || p.templateID.String != semgrepTpl.String() {
		t.Fatalf("organization semgrep finding: %+v", p)
	}

	// An older sensor (no mark, no prefix) running the organization's
	// template: the digest still says whose rules they are.
	ingestAs(finding("login-panel", ctis.Properties{"template_digest": "sha256:" + hashA}))
	if _, p = ruleProvenanceOf(t, r.db, tn.tenant, "login-panel"); p.source.String != "tenant" || p.templateID.String != nucleiTpl.String() {
		t.Fatalf("older sensor's organization finding: %+v", p)
	}

	// The read joins the template's current name in the finding's tenant
	// only; a deleted template keeps the source and version, without a
	// name.
	repo := postgres.NewFindingRepository(db)
	fid := shared.MustIDFromString(semgrepFinding)
	got, err := repo.RuleProvenance(context.Background(), tn.tenant, fid)
	if err != nil || got != (vulnerability.RuleProvenance{Source: "tenant", TemplateID: semgrepTpl.String(), TemplateName: "python-rules.yaml", TemplateVersion: "1.2.0"}) {
		t.Fatalf("RuleProvenance = %+v, %v", got, err)
	}
	if _, err := repo.RuleProvenance(context.Background(), other.tenant, fid); err == nil {
		t.Fatal("another tenant read the finding's rule provenance")
	}
	if _, err := r.db.Exec(`DELETE FROM scanner_templates WHERE id = $1`, semgrepTpl.String()); err != nil {
		t.Fatal(err)
	}
	if got, _ = repo.RuleProvenance(context.Background(), tn.tenant, fid); got.TemplateName != "" || got.Source != "tenant" {
		t.Fatalf("after delete: %+v", got)
	}
}
