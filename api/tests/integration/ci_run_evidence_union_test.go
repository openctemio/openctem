package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
)

// A pipeline run is the unit of evidence: retrying or re-running only the
// gate job used to open a new, empty run that judged nothing and passed, and
// the commit check took that latest verdict. Retries now re-open the run
// that holds every earlier report; the verdict is computed over the union
// with today's decisions; scanner failures of the earlier verdict count
// until a later attempt uploads; a run nothing was uploaded to fails.
func TestCIRunEvidenceUnion_GateRetryCannotPassOnNothing(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	repoName := strings.ToLower(strings.TrimPrefix(r.idp.srv.URL, "https://")) + "/acme/union"
	const sha = "5555555555555555555555555555555555555555"
	high := ciFinding("SQL injection", "go.sqli", "high", ctis.FindingTypeVulnerability, "db.go", 7)

	join := func(pipeline, job string) map[string]any {
		t.Helper()
		resp, out := r.post("/api/v1/ci/oidc/exchange", "", map[string]any{"tenant_id": r.tenant.String(),
			"id_token": r.idp.token(t, cfg.Audience, "acme/union", "feature/x", sha,
				map[string]any{"job_id": job, "pipeline_id": pipeline}), "aggregate": true})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("join %s/%s: %d %v", pipeline, job, resp.StatusCode, out)
		}
		return out
	}
	upload := func(run, tok string, fs ...ctis.Finding) {
		t.Helper()
		if resp, out := r.post("/api/v1/ci/runs/"+run+"/results", tok, ciReport(repoName, fs...)); resp.StatusCode != http.StatusCreated {
			t.Fatalf("upload: %d %v", resp.StatusCode, out)
		}
	}
	gate := func(run, tok string, failures int) map[string]any {
		t.Helper()
		resp, v := r.post("/api/v1/ci/runs/"+run+"/evaluate", tok, map[string]int{"scan_failures": failures})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("evaluate: %d %v", resp.StatusCode, v)
		}
		return v
	}

	// Pipeline run 2001: the scan job uploads a high finding, the gate fails.
	scan := join("2001", "1")
	run := scan["run_id"].(string)
	upload(run, scan["token"].(string), high)
	g := join("2001", "2")
	if v := gate(run, g["token"].(string), 0); v["verdict"] != "fail" {
		t.Fatalf("first gate: %v", v)
	}
	// Retrying only the gate job joins the same run (re-opened), and it is
	// judged on the scan job's report: still failing.
	retry := join("2001", "3")
	if retry["run_id"] != run {
		t.Fatalf("the gate retry opened another run: %v", retry)
	}
	if v := gate(run, retry["token"].(string), 0); v["verdict"] != "fail" {
		t.Fatalf("gate retry passed on nothing: %v", v)
	}
	var runs int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM ci_runs WHERE tenant_id = $1 AND commit_sha = $2 AND external_run_id = '2001'`,
		r.tenant.String(), sha).Scan(&runs); err != nil || runs != 1 {
		t.Fatalf("runs of the pipeline run: %d %v", runs, err)
	}
	// A decision made since (the finding is a false positive) turns the
	// re-run green without a new commit.
	if _, err := r.db.ExecContext(ctx, `UPDATE findings SET status = 'false_positive', resolution = 'false_positive'
		WHERE tenant_id = $1 AND rule_id = 'go.sqli'`, r.tenant.String()); err != nil {
		t.Fatal(err)
	}
	again := join("2001", "4")
	if v := gate(run, again["token"].(string), 0); v["verdict"] != "pass" {
		t.Fatalf("re-run after the decision: %v", v)
	}

	// Pipeline run 2002: a scanner failed. A gate-only retry that reports no
	// failure cannot drop it; a re-run of the scan that uploads clears it.
	s1 := join("2002", "1")
	run2 := s1["run_id"].(string)
	upload(run2, s1["token"].(string))
	if v := gate(run2, join("2002", "2")["token"].(string), 1); v["verdict"] != "fail" {
		t.Fatalf("scan failure: %v", v)
	}
	if v := gate(run2, join("2002", "3")["token"].(string), 0); v["verdict"] != "fail" || !hasReason(v, cirun.ReasonScanFailure) {
		t.Fatalf("gate retry dropped the scan failure: %v", v)
	}
	rescan := join("2002", "4")
	upload(run2, rescan["token"].(string))
	if v := gate(run2, join("2002", "5")["token"].(string), 0); v["verdict"] != "pass" {
		t.Fatalf("re-run scan did not clear the failure: %v", v)
	}

	// A run nothing was uploaded to fails, aggregate or not.
	empty := join("2003", "1")
	if v := gate(empty["run_id"].(string), empty["token"].(string), 0); v["verdict"] != "fail" || !hasReason(v, cirun.ReasonNoResults) {
		t.Fatalf("empty aggregate run: %v", v)
	}
	code, single := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/union", "feature/x", sha,
		map[string]any{"job_id": "9", "pipeline_id": "2004"}))
	if code != http.StatusCreated {
		t.Fatalf("single exchange: %d %v", code, single)
	}
	if v := gate(single["run_id"].(string), single["token"].(string), 0); v["verdict"] != "fail" || !hasReason(v, cirun.ReasonNoResults) {
		t.Fatalf("empty run: %v", v)
	}

	// Another tenant's job cannot join or re-open this pipeline run.
	resp, _ := r.post("/api/v1/ci/oidc/exchange", "", map[string]any{"tenant_id": r.other.String(),
		"id_token":  r.idp.token(t, cfg.Audience, "acme/union", "feature/x", sha, map[string]any{"job_id": "5", "pipeline_id": "2001"}),
		"aggregate": true})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("other tenant joined: %d", resp.StatusCode)
	}
}
