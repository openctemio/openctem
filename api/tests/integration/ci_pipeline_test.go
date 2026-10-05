package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// exchangeAs exchanges a token with a User-Agent (the runner's version).
func (r *ciRig) exchangeAs(tenant shared.ID, tok, ua string) (int, map[string]any) {
	r.t.Helper()
	b, _ := json.Marshal(map[string]string{"tenant_id": tenant.String(), "id_token": tok})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, r.srv.URL+"/api/v1/ci/oidc/exchange", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", ua)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (r *ciRig) pipelines(tenant shared.ID) []cirunapp.PipelineView {
	r.t.Helper()
	views, err := r.svc.AssessPipelines(context.Background(), tenant, cirun.PipelineFilter{})
	if err != nil {
		r.t.Fatal(err)
	}
	return views
}

func (r *ciRig) runPipeline(runID string) string {
	r.t.Helper()
	var id string
	if err := r.db.QueryRowContext(context.Background(), `SELECT COALESCE(pipeline_id::text, '') FROM ci_runs WHERE id = $1`, runID).Scan(&id); err != nil {
		r.t.Fatal(err)
	}
	return id
}

// TestCIPipelines is the fleet-identity acceptance through the real token
// verification: a pipeline per repository id and workflow file, created at
// an admitted exchange only, stable across renames and branches, fork runs
// attached and flagged, unverified identity refused, caps, revocation with
// the trust configuration, labels sanitized, no e-mail stored, tenant
// isolation (RFC-051).
func TestCIPipelines(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}, AllowForkPullRequests: true})
	aud := cfg.Audience
	host := strings.TrimPrefix(r.idp.srv.URL, "https://")
	const sha = "3333333333333333333333333333333333333333"
	const email = "dev.person@private-mail.example"

	// --- JIT creation at an admitted exchange ----------------------------
	code, ex := r.exchangeAs(r.tenant, r.idp.token(t, aud, "acme/api", "main", sha, map[string]any{"user_email": email}),
		"openctem-sensor/v0.9.1 openctem-sdk-go/v0.16.0")
	if code != http.StatusCreated {
		t.Fatalf("exchange: %d %v", code, ex)
	}
	ps := r.pipelines(r.tenant)
	if len(ps) != 1 || ps[0].ExternalRepoID != "7" || ps[0].WorkflowPath != cirun.GitLabDefaultConfigPath ||
		ps[0].RepositoryName != strings.ToLower(host)+"/acme/api" || ps[0].SensorVersion != "v0.9.1" {
		t.Fatalf("pipelines = %+v", ps)
	}
	pid := ps[0].ID.String()
	if r.runPipeline(ex["run_id"].(string)) != pid {
		t.Fatal("run not linked to its pipeline")
	}
	if r.auditCount(r.tenant, "ci_pipeline.created", "workflow_path") != 1 {
		t.Fatal("pipeline creation not audited")
	}
	if st := ps[0].Assessment.Status; st != cirun.PipelineRunning {
		t.Fatalf("status after exchange = %s", st)
	}
	// Refused tokens never create a pipeline.
	if code, _ := r.exchange(r.tenant, r.idp.token(t, aud, "evil/api", "main", sha, map[string]any{"project_id": "99"})); code != http.StatusUnauthorized {
		t.Fatalf("other owner: %d", code)
	}
	if len(r.pipelines(r.tenant)) != 1 {
		t.Fatal("a refused token created a pipeline")
	}

	// --- branch explosion: branches are attributes, not identities -------
	for i := 0; i < 25; i++ {
		if code, out := r.exchange(r.tenant, r.idp.token(t, aud, "acme/api", fmt.Sprintf("feature/f%d", i), sha, nil)); code != http.StatusCreated {
			t.Fatalf("branch %d: %d %v", i, code, out)
		}
	}
	if n := len(r.pipelines(r.tenant)); n != 1 {
		t.Fatalf("25 branches made %d pipelines", n)
	}
	branches, err := r.svc.PipelineBranches(ctx, r.tenant, ps[0].ID)
	if err != nil || len(branches) != 26 || branches[0].Branch != "main" || !branches[0].IsDefaultBranch {
		t.Fatalf("branches = %d %v (%+v)", len(branches), err, branches[:1])
	}

	// --- rename: the same project id keeps the pipeline ------------------
	if code, out := r.exchange(r.tenant, r.idp.token(t, aud, "acme/api-renamed", "main", sha, nil)); code != http.StatusCreated {
		t.Fatalf("renamed: %d %v", code, out)
	}
	ps = r.pipelines(r.tenant)
	if len(ps) != 1 || ps[0].ID.String() != pid || !strings.HasSuffix(ps[0].RepositoryName, "/acme/api-renamed") {
		t.Fatalf("after rename = %+v", ps)
	}
	// Another workflow file of the same project: a second pipeline.
	other := map[string]any{"ci_config_ref_uri": host + "/acme/api-renamed//ci/security.yml@refs/heads/main"}
	if code, out := r.exchange(r.tenant, r.idp.token(t, aud, "acme/api-renamed", "main", sha, other)); code != http.StatusCreated {
		t.Fatalf("second workflow: %d %v", code, out)
	}
	if n := len(r.pipelines(r.tenant)); n != 2 {
		t.Fatalf("pipelines after a second workflow = %d", n)
	}

	// --- forged or unverifiable identity ---------------------------------
	for _, over := range []map[string]any{{"project_id": nil}, {"project_id": "acme/api"}, {"ci_config_ref_uri": host + "/acme/api//../../x@refs/heads/main"}} {
		if code, _ := r.exchange(r.tenant, r.idp.token(t, aud, "acme/api", "main", sha, over)); code != http.StatusUnauthorized {
			t.Fatalf("identity %v admitted: %d", over, code)
		}
	}
	if r.auditCount(r.tenant, "ci_run.token_refused", cirun.RefusePipelineIdentity) != 3 {
		t.Fatal("identity refusals not audited")
	}
	if n := len(r.pipelines(r.tenant)); n != 2 {
		t.Fatalf("an unverifiable token created a pipeline (%d)", n)
	}

	// --- fork runs attach to the upstream pipeline, flagged --------------
	before := r.pipelines(r.tenant)
	code, fx := r.exchange(r.tenant, r.idp.token(t, aud, "acme/api-renamed", "main", sha,
		map[string]any{"pipeline_source": "external_pull_request_event"}))
	if code != http.StatusCreated {
		t.Fatalf("fork run: %d %v", code, fx)
	}
	var fork bool
	_ = r.db.QueryRowContext(ctx, `SELECT fork FROM ci_runs WHERE id = $1`, fx["run_id"]).Scan(&fork)
	if !fork || r.runPipeline(fx["run_id"].(string)) != pid {
		t.Fatal("fork run not attached to the upstream pipeline as a fork")
	}
	p, err := r.svc.GetPipeline(ctx, r.tenant, ps[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	var beforeRuns int
	for _, b := range before {
		if b.ID == p.ID {
			beforeRuns = b.RunsCount
		}
	}
	if p.LastForkRunAt == nil || p.RunsCount != beforeRuns {
		t.Fatalf("fork run counted as the pipeline's own: runs %d -> %d, fork at %v", beforeRuns, p.RunsCount, p.LastForkRunAt)
	}
	// A fork run's verdict never sets the default-branch gate.
	ftok := fx["token"].(string)
	if resp, v := r.post("/api/v1/ci/runs/"+fx["run_id"].(string)+"/evaluate", ftok, map[string]int{"scan_failures": 1}); resp.StatusCode != http.StatusOK || v["verdict"] != "fail" {
		t.Fatalf("fork evaluate: %d %v", resp.StatusCode, v)
	}
	if p, _ = r.svc.GetPipeline(ctx, r.tenant, ps[0].ID); p.LastDefaultVerdict != "" {
		t.Fatalf("fork verdict set the default-branch gate: %q", p.LastDefaultVerdict)
	}

	// --- gate and health from the pipeline's own runs ---------------------
	code, mx := r.exchangeAs(r.tenant, r.idp.token(t, aud, "acme/api-renamed", "main", sha, nil), "openctem-sensor/v0.9.1")
	if code != http.StatusCreated {
		t.Fatalf("main run: %d", code)
	}
	mtok, mrun := mx["token"].(string), mx["run_id"].(string)
	rep := ciReport(mx["repository"].(string))
	rep["report"] = func() ctis.Report {
		rp := rep["report"].(ctis.Report)
		rp.Tool = &ctis.Tool{Name: "Sem<grep>\u202e", Version: "1.2.3\x00evil"}
		return rp
	}()
	if resp, out := r.post("/api/v1/ci/runs/"+mrun+"/results", mtok, rep); resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload: %d %v", resp.StatusCode, out)
	}
	if resp, v := r.post("/api/v1/ci/runs/"+mrun+"/evaluate", mtok, map[string]int{"scan_failures": 2}); resp.StatusCode != http.StatusOK {
		t.Fatalf("evaluate: %d %v", resp.StatusCode, v)
	}
	p, _ = r.svc.GetPipeline(ctx, r.tenant, ps[0].ID)
	if p.LastDefaultVerdict != cirun.VerdictFail || p.LastScanFailures == nil || *p.LastScanFailures != 2 ||
		p.Assessment.Status != cirun.PipelineFailing || p.Assessment.Health != cirun.HealthDegraded {
		t.Fatalf("pipeline after a failing default-branch run = %+v / %+v", p.Pipeline, p.Assessment)
	}
	if len(p.Tools) != 1 || p.Tools[0].Name != "semgrep" || strings.ContainsAny(p.Tools[0].Version, "\x00<>") {
		t.Fatalf("tools not sanitized: %+v", p.Tools)
	}
	trend, err := r.svc.PipelineGateTrend(ctx, r.tenant, ps[0].ID, 10)
	if err != nil || len(trend) != 1 || trend[0].Verdict != cirun.VerdictFail {
		t.Fatalf("gate trend = %+v %v", trend, err)
	}

	// --- no e-mail stored anywhere ---------------------------------------
	var leaked int
	_ = r.db.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM ci_runs WHERE tenant_id = $1 AND row_to_json(ci_runs)::text LIKE '%' || $2 || '%') +
		(SELECT count(*) FROM ci_pipelines WHERE tenant_id = $1 AND row_to_json(ci_pipelines)::text LIKE '%' || $2 || '%') +
		(SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND row_to_json(audit_logs)::text LIKE '%' || $2 || '%')`,
		r.tenant.String(), email).Scan(&leaked)
	if leaked != 0 {
		t.Fatalf("the token's user_email was stored in %d rows", leaked)
	}

	// --- tenant isolation, the fleet union included ----------------------
	if _, err := r.svc.GetPipeline(ctx, r.other, ps[0].ID); err == nil {
		t.Fatal("another tenant read the pipeline")
	}
	if n := len(r.pipelines(r.other)); n != 0 {
		t.Fatalf("another tenant lists %d pipelines", n)
	}
	if b, err := r.svc.PipelineBranches(ctx, r.other, ps[0].ID); err != nil || len(b) != 0 {
		t.Fatalf("another tenant reads the branches: %d %v", len(b), err)
	}
	admin := handler.NewCIAdminHandler(r.svc, nil, logger.NewNop())
	admin.SetPipelineService(r.svc)
	if rows, err := admin.FleetRunners(ctx, r.other); err != nil || len(rows) != 0 {
		t.Fatalf("another tenant's fleet lists %d runner rows (%v)", len(rows), err)
	}
	if rows, err := admin.FleetRunners(ctx, r.tenant); err != nil || len(rows) != 2 || rows[0].Mode != handler.FleetModeRunner {
		t.Fatalf("own fleet rows = %d %v", len(rows), err)
	}
	if runs, total, err := r.svc.ListRuns(ctx, r.other, cirun.RunFilter{PipelineID: &ps[0].ID}); err != nil || total != 0 || len(runs) != 0 {
		t.Fatalf("another tenant lists the pipeline's runs: %d %v", total, err)
	}
	var sensors int
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM sensors WHERE tenant_id = $1`, r.tenant.String()).Scan(&sensors)
	if sensors != 0 {
		t.Fatalf("pipelines created %d sensor rows", sensors)
	}

	// --- revoking the trust configuration revokes its pipelines -----------
	code, lx := r.exchange(r.tenant, r.idp.token(t, aud, "acme/api-renamed", "main", sha, nil))
	if code != http.StatusCreated {
		t.Fatalf("in-flight run: %d", code)
	}
	off := false
	if _, err := r.svc.UpdateTrustConfig(ctx, r.tenant, cfg.ID, cirunapp.TrustConfigInput{Name: cfg.Name, Issuer: cfg.Issuer,
		Audience: cfg.Audience, DefaultBranch: cfg.DefaultBranch, Rules: cfg.Rules, Enabled: &off}, cirunapp.Actor{Email: "admin@acme.test"}); err != nil {
		t.Fatal(err)
	}
	for _, v := range r.pipelines(r.tenant) {
		if v.RevokedAt == nil || v.Assessment.Status != cirun.PipelineRevoked || !v.Assessment.Status.IsInactive() {
			t.Fatalf("pipeline not revoked: %+v", v.Assessment)
		}
	}
	if resp, _ := r.post("/api/v1/ci/runs/"+lx["run_id"].(string)+"/evaluate", lx["token"].(string), nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an in-flight run token survived the revocation: %d", resp.StatusCode)
	}
	if r.auditCount(r.tenant, "ci_pipeline.revoked", "pipelines") != 1 {
		t.Fatal("revocation not audited")
	}
	// Re-enabled: the next admitted run revives its pipeline.
	on := true
	if _, err := r.svc.UpdateTrustConfig(ctx, r.tenant, cfg.ID, cirunapp.TrustConfigInput{Name: cfg.Name, Issuer: cfg.Issuer,
		Audience: cfg.Audience, DefaultBranch: cfg.DefaultBranch, Rules: cfg.Rules, Enabled: &on}, cirunapp.Actor{}); err != nil {
		t.Fatal(err)
	}
	if code, _ := r.exchange(r.tenant, r.idp.token(t, aud, "acme/api-renamed", "main", sha, nil)); code != http.StatusCreated {
		t.Fatalf("after re-enable: %d", code)
	}
	if p, _ = r.svc.GetPipeline(ctx, r.tenant, ps[0].ID); p.RevokedAt != nil {
		t.Fatal("an admitted run did not revive its pipeline")
	}
	// Deleting the configuration revokes too.
	if err := r.svc.DeleteTrustConfig(ctx, r.tenant, cfg.ID, cirunapp.Actor{}); err != nil {
		t.Fatal(err)
	}
	if p, _ = r.svc.GetPipeline(ctx, r.tenant, ps[0].ID); p.RevokedAt == nil {
		t.Fatal("deleting the trust configuration left the pipeline active")
	}
}

// TestCIPipelineCaps: a tenant at its cap gets no new pipeline (refused and
// audited); its existing pipelines keep running.
func TestCIPipelineCaps(t *testing.T) {
	r := newCIRigWith(t, cirunapp.Config{PipelineCaps: cirun.PipelineCaps{PerTenant: 1, PerTrustConfig: 1}})
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	const sha = "4444444444444444444444444444444444444444"
	if code, _ := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/api", "main", sha, nil)); code != http.StatusCreated {
		t.Fatalf("first pipeline: %d", code)
	}
	if code, _ := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/web", "main", sha, map[string]any{"project_id": "8"})); code != http.StatusUnauthorized {
		t.Fatalf("over the cap: %d", code)
	}
	if r.auditCount(r.tenant, "ci_run.token_refused", "pipeline_cap") != 1 {
		t.Fatal("cap refusal not audited")
	}
	if code, _ := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/api", "dev", sha, nil)); code != http.StatusCreated {
		t.Fatalf("existing pipeline refused at the cap: %d", code)
	}
	if n := len(r.pipelines(r.tenant)); n != 1 {
		t.Fatalf("pipelines = %d", n)
	}
}
