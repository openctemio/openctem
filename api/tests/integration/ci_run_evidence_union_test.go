package integration

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
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

// Re-opening a failed run (a later attempt joined it) must never hide its
// verdict: the commit check and the "merged without a passing gate" check
// keep reading its last verdict until it is judged again. Two pipelines on
// one commit: P1 fails, P2 passes; a retry of one of P1's scan jobs re-opens
// P1; the commit still fails.
func TestCIRunEvidenceUnion_ReopenKeepsTheVerdict(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	repoName := strings.ToLower(strings.TrimPrefix(r.idp.srv.URL, "https://")) + "/acme/twopipes"
	const sha = "7777777777777777777777777777777777777770"
	join := func(workflow, pipeline, job string) map[string]any {
		t.Helper()
		resp, out := r.post("/api/v1/ci/oidc/exchange", "", map[string]any{"tenant_id": r.tenant.String(),
			"id_token": r.idp.token(t, cfg.Audience, "acme/twopipes", "feature/x", sha,
				map[string]any{"job_id": job, "pipeline_id": pipeline, "ci_config_ref_uri": strings.TrimPrefix(r.idp.srv.URL, "https://") + "/acme/twopipes//" + workflow + "@refs/heads/feature/x"}),
			"aggregate": true})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("join: %d %v", resp.StatusCode, out)
		}
		return out
	}
	judge := func(run, tok string, fs ...ctis.Finding) map[string]any {
		t.Helper()
		if resp, out := r.post("/api/v1/ci/runs/"+run+"/results", tok, ciReport(repoName, fs...)); resp.StatusCode != http.StatusCreated {
			t.Fatalf("upload: %d %v", resp.StatusCode, out)
		}
		_, v := r.post("/api/v1/ci/runs/"+run+"/evaluate", tok, map[string]int{"scan_failures": 0})
		return v
	}
	p1 := join(".gitlab-ci.yml", "3001", "1")
	run1 := p1["run_id"].(string)
	if v := judge(run1, p1["token"].(string), ciFinding("SQL injection", "go.sqli", "high", ctis.FindingTypeVulnerability, "db.go", 7)); v["verdict"] != "fail" {
		t.Fatalf("P1: %v", v)
	}
	p2 := join("ci/security.yml", "3002", "1")
	if p2["run_id"] == run1 {
		t.Fatal("two pipeline runs share one run")
	}
	if v := judge(p2["run_id"].(string), p2["token"].(string)); v["verdict"] != "pass" {
		t.Fatalf("P2: %v", v)
	}
	if _, err := r.db.ExecContext(ctx, `UPDATE ci_runs SET pull_request = '7' WHERE tenant_id = $1 AND id = $2`, r.tenant.String(), run1); err != nil {
		t.Fatal(err)
	}
	run, err := r.svc.GetRun(ctx, r.tenant, shared.MustIDFromString(run1))
	if err != nil {
		t.Fatal(err)
	}
	// A retry of one of P1's scan jobs re-opens P1.
	if retry := join(".gitlab-ci.yml", "3001", "2"); retry["run_id"] != run1 {
		t.Fatalf("retry did not re-open P1: %v", retry)
	}
	var status string
	_ = r.db.QueryRowContext(ctx, `SELECT status FROM ci_runs WHERE id = $1`, run1).Scan(&status)
	if status != string(cirun.StatusRunning) {
		t.Fatalf("P1 status %s, want running", status)
	}
	vs, err := r.repo.CommitVerdicts(ctx, r.tenant, run.RepositoryAssetID, []string{sha})
	if err != nil {
		t.Fatal(err)
	}
	failed := false
	for _, v := range vs {
		if v.RunID.String() == run1 && v.Verdict == cirun.VerdictFail {
			failed = true
		}
	}
	if !failed {
		t.Fatalf("the re-opened failed run dropped out of the commit verdicts: %+v", vs)
	}
	if ok, err := r.repo.PullRequestPassed(ctx, r.tenant, run.RepositoryAssetID, "7"); err != nil || ok {
		t.Fatalf("the re-opened failed run counts as a passed pull request: %v %v", ok, err)
	}
}

// A capability that failed in an earlier attempt keeps failing the pipeline
// run until a report of THAT capability arrives: a report of another
// capability does not clear it, and the evaluating job cannot clear it by
// saying it uploaded.
func TestCIRunEvidenceUnion_FailedCapabilityCarriedUntilItReports(t *testing.T) {
	r := newCIRig(t)
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	repoName := strings.ToLower(strings.TrimPrefix(r.idp.srv.URL, "https://")) + "/acme/caps"
	const sha = "8888888888888888888888888888888888888880"
	join := func(job string) (string, string) {
		t.Helper()
		resp, out := r.post("/api/v1/ci/oidc/exchange", "", map[string]any{"tenant_id": r.tenant.String(),
			"id_token":  r.idp.token(t, cfg.Audience, "acme/caps", "feature/x", sha, map[string]any{"job_id": job, "pipeline_id": "4001"}),
			"aggregate": true})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("join: %d %v", resp.StatusCode, out)
		}
		return out["run_id"].(string), out["token"].(string)
	}
	upload := func(run, tok, tool string) {
		t.Helper()
		rep := ciReport(repoName)
		rep["report"].(ctis.Report).Tool.Name = tool
		if resp, out := r.post("/api/v1/ci/runs/"+run+"/results", tok, rep); resp.StatusCode != http.StatusCreated {
			t.Fatalf("upload %s: %d %v", tool, resp.StatusCode, out)
		}
	}
	gate := func(run, tok string, secretsState string) map[string]any {
		t.Helper()
		caps := []map[string]string{{"name": "sast", "tool": "semgrep", "state": "uploaded"},
			{"name": "secrets", "tool": "betterleaks", "state": secretsState}}
		_, v := r.post("/api/v1/ci/runs/"+run+"/evaluate", tok, map[string]any{"scan_failures": 0, "capabilities": caps})
		return v
	}
	run, tok := join("1")
	upload(run, tok, "semgrep")
	if v := gate(run, tok, "failed"); v["verdict"] != "fail" || !hasReason(v, cirun.ReasonCapabilityFailed) {
		t.Fatalf("secrets failed: %v", v)
	}
	// Re-run of the sast job only: a sast report does not clear secrets;
	// the gate job says everything uploaded: still failing.
	run2, tok2 := join("2")
	if run2 != run {
		t.Fatal("the retry opened another run")
	}
	upload(run, tok2, "semgrep")
	if v := gate(run, tok2, "uploaded"); v["verdict"] != "fail" || !hasReason(v, cirun.ReasonCapabilityFailed) {
		t.Fatalf("a sast report cleared the failed secrets scan: %v", v)
	}
	// The secrets scan re-runs and reports: cleared, the run passes.
	_, tok3 := join("3")
	upload(run, tok3, "betterleaks")
	if v := gate(run, tok3, "uploaded"); v["verdict"] != "pass" {
		t.Fatalf("after the secrets report: %v", v)
	}
}

// Many jobs released at once by a barrier, round after round, each opening
// the same new pipeline run: every one gets the one run, none an error.
// Two inserts that both pass the ON CONFLICT pre-check race to insert their
// index entries; a second unique index that matches the row (not the
// ON CONFLICT arbiter) then raises a unique violation for the loser instead
// of letting it fall back to DO NOTHING.
func TestCIRunEvidenceUnion_ConcurrentJoinsGetOneRun(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	const sha = "9999999999999999999999999999999999999991"
	resp, out := r.post("/api/v1/ci/oidc/exchange", "", map[string]any{"tenant_id": r.tenant.String(),
		"id_token":  r.idp.token(t, cfg.Audience, "acme/racing", "main", sha, map[string]any{"job_id": "1", "pipeline_id": "6000"}),
		"aggregate": true})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("seed: %d %v", resp.StatusCode, out)
	}
	seed, err := r.svc.GetRun(ctx, r.tenant, shared.MustIDFromString(out["run_id"].(string)))
	if err != nil {
		t.Fatal(err)
	}
	const rounds, jobs = 150, 12
	for round := range rounds {
		start := make(chan struct{})
		var wg sync.WaitGroup
		ids := make([]shared.ID, jobs)
		errs := make([]error, jobs)
		for j := range jobs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				join := *seed
				join.ID, join.ExternalRunID, join.RunAttempt, join.TokenHash, join.TokenExpiresAt =
					shared.NewID(), fmt.Sprintf("6%04d", round+1), "1", nil, nil
				<-start
				got, _, err := r.repo.OpenAggregateRun(ctx, &join)
				errs[j] = err
				if got != nil {
					ids[j] = got.ID
				}
			}()
		}
		close(start)
		wg.Wait()
		for j := range jobs {
			if errs[j] != nil || ids[j] != ids[0] {
				t.Fatalf("round %d job %d: %v (runs %v)", round, j, errs[j], ids)
			}
		}
	}
}
