package integration

// A false positive on a taint finding is an argument about its source. When
// a re-scan reports the same finding (same sink) from another source, the
// decision stands and is flagged for review (a person decides): one open
// review flag, audited. A refactor of the steps in between raises nothing;
// another tenant is untouched.

import (
	"context"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestTaintSourceChange_FlagsTheDecisionForReview(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	db := &postgres.DB{DB: r.db}
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	svc.SetDataFlowRepository(postgres.NewDataFlowRepository(db))
	ctx := context.Background()
	ingestAs := func(tn v2Tenant, rep *ctis.Report) {
		t.Helper()
		tid := tn.tenant
		agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
		if _, err := svc.Ingest(ctx, agt, ingest.Input{Report: rep}); err != nil {
			t.Fatal(err)
		}
	}
	withSource := func(path, code string, steps int) *ctis.DataFlow {
		df := flowOf(path, steps)
		df.Sources[0].Content = code
		return df
	}
	status := func(tn v2Tenant) string {
		var s string
		_ = r.db.QueryRow(`SELECT status FROM findings WHERE tenant_id = $1`, tn.tenant.String()).Scan(&s)
		return s
	}
	tn, other := r.newTenant("semgrep"), r.newTenant("semgrep")
	for _, x := range []v2Tenant{tn, other} {
		repo := "github.com/acme/" + x.tenant.String()[:8]
		ingestAs(x, flowReport(repo, withSource("src/config.js", "const id = process.env.ID", 4)))
		if _, err := r.db.Exec(`UPDATE findings SET status = 'false_positive' WHERE tenant_id = $1`, x.tenant.String()); err != nil {
			t.Fatal(err)
		}
	}
	repo := "github.com/acme/" + tn.tenant.String()[:8]

	// The steps in between change (a refactor): the decision holds.
	ingestAs(tn, flowReport(repo, withSource("src/config.js", "const id = process.env.ID", 6)))
	if st := status(tn); st != "false_positive" {
		t.Fatalf("a refactor of the trace suspended the decision: %s", st)
	}
	var flags int
	_ = r.db.QueryRow(`SELECT count(*) FROM finding_decision_reviews WHERE tenant_id = $1`, tn.tenant.String()).Scan(&flags)
	if flags != 0 {
		t.Fatalf("a refactor of the trace raised %d review flags, want 0", flags)
	}
	// The source changes to user input: the decision stands, flagged for review.
	ingestAs(tn, flowReport(repo, withSource("src/routes.js", "const id = req.query.id", 6)))
	if st := status(tn); st != "false_positive" {
		t.Fatalf("status after the source changed: %s, want false_positive (the decision stands)", st)
	}
	var kept, audits int
	_ = r.db.QueryRow(`SELECT count(*) FROM finding_decision_reviews WHERE tenant_id = $1 AND decision_status = 'false_positive'
		AND reason = 'taint_source_changed' AND cleared_at IS NULL`, tn.tenant.String()).Scan(&kept)
	_ = r.db.QueryRow(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding.status_changed'
		AND metadata->>'reason' = 'taint_source_changed'`, tn.tenant.String()).Scan(&audits)
	if kept != 1 || audits != 1 {
		t.Fatalf("open review flags %d, audit rows %d; want 1 and 1", kept, audits)
	}
	// Another tenant's decision is untouched.
	if st := status(other); st != "false_positive" {
		t.Fatalf("another tenant's decision changed: %s", st)
	}
}
