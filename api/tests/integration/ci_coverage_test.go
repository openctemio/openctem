package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/internal/app/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type ciAlertCapture struct{ sent []outbox.EnqueueParams }

func (c *ciAlertCapture) Enqueue(_ context.Context, p outbox.EnqueueParams) error {
	c.sent = append(c.sent, p)
	return nil
}

func (c *ciAlertCapture) count(eventType string) int {
	n := 0
	for _, p := range c.sent {
		if p.EventType == eventType {
			n++
		}
	}
	return n
}

// TestCICoverageAndAlerts: coverage from a real CI run's reported tools,
// expectations, the alert job (once per condition, cleared when it stops
// holding, tenant-isolated), stale-source findings and retirement
// (RFC-051 §10.6).
func TestCICoverageAndAlerts(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	const sha = "5555555555555555555555555555555555555555"

	code, ex := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/api", "main", sha, nil))
	if code != http.StatusCreated {
		t.Fatalf("exchange: %d %v", code, ex)
	}
	token, runID, repoName := ex["token"].(string), ex["run_id"].(string), ex["repository"].(string)
	assetID := shared.MustIDFromString(ex["repository_asset_id"].(string))
	secret := ciFinding("AWS key", "aws-access-key", "high", ctis.FindingTypeSecret, "config.go", 3)
	rep := ciReport(repoName, secret) // tool: semgrep (sast)
	if resp, out := r.post("/api/v1/ci/runs/"+runID+"/results", token, rep); resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload: %d %v", resp.StatusCode, out)
	}
	if resp, v := r.post("/api/v1/ci/runs/"+runID+"/evaluate", token, nil); resp.StatusCode != http.StatusOK || v["verdict"] != "fail" {
		t.Fatalf("evaluate: %d %v", resp.StatusCode, v)
	}

	// --- coverage -------------------------------------------------------
	cov, err := r.svc.Coverage(ctx, r.tenant, cirunapp.CoverageInput{})
	if err != nil {
		t.Fatal(err)
	}
	if cov.Summary.Repositories != 1 || cov.Summary.Covered != 1 || cov.Summary.FreshByCapability[cirun.CapabilitySAST] != 1 {
		t.Fatalf("coverage summary = %+v", cov.Summary)
	}
	// Expect secrets too: a gap until something reports it.
	if _, err := r.svc.SetExpectation(ctx, r.tenant, assetID, []string{"sast", "secrets"}, cirunapp.Actor{Email: "admin@acme.test"}); err != nil {
		t.Fatal(err)
	}
	if cov, _ = r.svc.Coverage(ctx, r.tenant, cirunapp.CoverageInput{Filter: cirunapp.CoverageFilterGap}); cov.Total != 1 || !cov.Items[0].Gap {
		t.Fatalf("gap listing = %+v", cov)
	}
	// Another tenant: no repositories, cannot mark ours.
	if oc, _ := r.svc.Coverage(ctx, r.other, cirunapp.CoverageInput{}); oc.Summary.Repositories != 0 {
		t.Fatal("another tenant sees the repository")
	}
	if _, err := r.svc.SetExpectation(ctx, r.other, assetID, nil, cirunapp.Actor{}); err == nil {
		t.Fatal("another tenant marked our repository")
	}
	if _, err := r.svc.SetExpectation(ctx, r.tenant, assetID, []string{"dast"}, cirunapp.Actor{}); err == nil {
		t.Fatal("a non-repository capability accepted")
	}

	// --- alerts ---------------------------------------------------------
	n := &ciAlertCapture{}
	job := cirunapp.NewAlertJob(r.repo, n, nil, cirun.StatusPolicy{}, logger.NewNop())
	now := time.Now().UTC()
	job.SetClock(func() time.Time { return now })
	if _, err := job.ReconcileTenant(ctx, r.tenant); err != nil {
		t.Fatal(err)
	}
	if n.count("ci.gate_failing") != 1 {
		t.Fatalf("gate failing alert: %+v", n.sent)
	}
	// Again: no repeat while the condition holds.
	if _, err := job.ReconcileTenant(ctx, r.tenant); err != nil || n.count("ci.gate_failing") != 1 {
		t.Fatalf("gate failing repeated: %d %v", n.count("ci.gate_failing"), err)
	}
	// Eight days later the pipeline is stale: the repository lost coverage,
	// and the finding only this pipeline reported is not observed.
	job.SetClock(func() time.Time { return now.Add(8 * 24 * time.Hour) })
	res, err := job.ReconcileTenant(ctx, r.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if n.count("ci.coverage_regression") != 1 || res.StaleFindings != 1 {
		t.Fatalf("after 8 days: %+v, sent %+v", res, n.sent)
	}
	var st, why string
	_ = r.db.QueryRowContext(ctx, `SELECT status, COALESCE(resolution, '') FROM findings WHERE tenant_id = $1 AND title = 'AWS key'`,
		r.tenant.String()).Scan(&st, &why)
	if st != "not_observed" || why != "source_stale" {
		t.Fatalf("stale-source finding = %s/%s", st, why)
	}
	for _, p := range n.sent {
		if p.TenantID != r.tenant {
			t.Fatal("an alert went to another tenant")
		}
	}
	// The other tenant has no pipelines: nothing for it.
	if res, err := job.ReconcileTenant(ctx, r.other); err != nil || res.Fired != 0 {
		t.Fatalf("other tenant alerts: %+v %v", res, err)
	}
	// Back to now: the regression clears (and can fire again later).
	job.SetClock(func() time.Time { return now })
	if res, _ := job.ReconcileTenant(ctx, r.tenant); res.Cleared != 1 {
		t.Fatalf("regression not cleared: %+v", res)
	}

	// --- retire ---------------------------------------------------------
	pipes, _ := r.svc.AssessPipelines(ctx, r.tenant, cirun.PipelineFilter{})
	if len(pipes) != 1 {
		t.Fatalf("pipelines = %d", len(pipes))
	}
	if _, _, err := r.svc.RetirePipeline(ctx, r.tenant, pipes[0].ID, "short", cirunapp.Actor{}); err == nil {
		t.Fatal("retired without a reason")
	}
	if _, _, err := r.svc.RetirePipeline(ctx, r.other, pipes[0].ID, "not my pipeline at all", cirunapp.Actor{}); err == nil {
		t.Fatal("another tenant retired the pipeline")
	}
	_, closed, err := r.svc.RetirePipeline(ctx, r.tenant, pipes[0].ID, "the workflow was removed from the repo", cirunapp.Actor{Email: "admin@acme.test"})
	if err != nil || len(closed) != 1 {
		t.Fatalf("retire: %v %v", closed, err)
	}
	_ = r.db.QueryRowContext(ctx, `SELECT status, COALESCE(resolution, '') FROM findings WHERE tenant_id = $1 AND title = 'AWS key'`,
		r.tenant.String()).Scan(&st, &why)
	if st != "resolved" || why != "source_retired" {
		t.Fatalf("retired-source finding = %s/%s", st, why)
	}
	if r.auditCount(r.tenant, "ci_pipeline.retired", "workflow was removed") != 1 {
		t.Fatal("retirement not audited")
	}
	// A retired pipeline raises no alert.
	before := len(n.sent)
	if _, err := job.ReconcileTenant(ctx, r.tenant); err != nil || len(n.sent) != before {
		t.Fatalf("retired pipeline alerted: %v", n.sent[before:])
	}
	if !strings.HasPrefix(n.sent[0].URL, "/sensors?mode=runner") {
		t.Fatalf("alert link = %q", n.sent[0].URL)
	}
}
