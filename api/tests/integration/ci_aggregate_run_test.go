package integration

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
)

// TestCIRunner_AggregateRun: the parallel capability jobs of one pipeline
// run report into one run, each with its own token, and one final job gets
// the verdict on all of them (RFC-051, aggregate runs).
func TestCIRunner_AggregateRun(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}, Refs: []string{"main"}})
	aud := cfg.Audience
	const sha = "3333333333333333333333333333333333333333"
	const sha2 = "4444444444444444444444444444444444444444"
	repoName := strings.ToLower(strings.TrimPrefix(r.idp.srv.URL, "https://")) + "/acme/api"

	join := func(over map[string]any, commit string) (int, map[string]any) {
		t.Helper()
		resp, out := r.post("/api/v1/ci/oidc/exchange", "", map[string]any{"tenant_id": r.tenant.String(),
			"id_token": r.idp.token(t, aud, "acme/api", "main", commit, over), "aggregate": true})
		return resp.StatusCode, out
	}
	upload := func(run, token string, f ctis.Finding) int {
		t.Helper()
		resp, _ := r.post("/api/v1/ci/runs/"+run+"/results", token, ciReport(repoName, f))
		return resp.StatusCode
	}

	// Two capability jobs of pipeline 1001 join one run, each with its own token.
	codeA, a := join(map[string]any{"job_id": "601"}, sha)
	codeB, b := join(map[string]any{"job_id": "602"}, sha)
	if codeA != http.StatusCreated || codeB != http.StatusCreated {
		t.Fatalf("aggregate exchanges: %d %v / %d %v", codeA, a, codeB, b)
	}
	run, tokA, tokB := a["run_id"].(string), a["token"].(string), b["token"].(string)
	if b["run_id"] != run || a["aggregate"] != true || b["aggregate"] != true || tokA == tokB {
		t.Fatalf("jobs did not join one run with their own tokens: %v / %v", a, b)
	}
	// The first job's token still works after the second joined.
	if c := upload(run, tokB, ciFinding("Weak hash", "go.weak-hash", "medium", ctis.FindingTypeVulnerability, "hash.go", 10)); c != http.StatusCreated {
		t.Fatalf("upload job B: %d", c)
	}
	if c := upload(run, tokA, ciFinding("SQL injection", "go.sqli", "high", ctis.FindingTypeVulnerability, "db.go", 7)); c != http.StatusCreated {
		t.Fatalf("upload job A: %d", c)
	}
	var tokens, runs int
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM ci_run_tokens WHERE tenant_id = $1 AND run_id = $2`, r.tenant.String(), run).Scan(&tokens)
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM ci_runs WHERE tenant_id = $1 AND commit_sha = $2`, r.tenant.String(), sha).Scan(&runs)
	if tokens != 2 || runs != 1 {
		t.Fatalf("tokens %d runs %d, want 2 and 1", tokens, runs)
	}

	// Many jobs racing to open the run of pipeline 1003 all get the same run.
	var wg sync.WaitGroup
	ids := make([]string, 8)
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, out := join(map[string]any{"job_id": "70" + string(rune('0'+i)), "pipeline_id": "1003"}, sha)
			ids[i], _ = out["run_id"].(string)
		}(i)
	}
	wg.Wait()
	for _, id := range ids {
		if id == "" || id != ids[0] {
			t.Fatalf("racing jobs got different runs: %v", ids)
		}
	}
	if ids[0] == run {
		t.Fatal("another pipeline run joined the first one")
	}

	// Another commit, or a job that does not ask for aggregate: its own run.
	if _, o := join(map[string]any{"job_id": "603"}, sha2); o["run_id"] == run {
		t.Fatal("another commit joined the run")
	}
	if code, o := r.exchange(r.tenant, r.idp.token(t, aud, "acme/api", "main", sha, map[string]any{"job_id": "604"})); code != http.StatusCreated ||
		o["run_id"] == run || o["aggregate"] != false {
		t.Fatalf("a per-job exchange joined the aggregate run: %d %v", code, o)
	}
	// Another tenant cannot join (no trust in the issuer there).
	resp, _ := r.post("/api/v1/ci/oidc/exchange", "", map[string]any{"tenant_id": r.other.String(),
		"id_token": r.idp.token(t, aud, "acme/api", "main", sha, map[string]any{"job_id": "605"}), "aggregate": true})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("other tenant: %d", resp.StatusCode)
	}
	// A token without a pipeline run id cannot join anything.
	if code, _ := join(map[string]any{"job_id": "606", "pipeline_id": nil}, sha); code != http.StatusUnauthorized {
		t.Fatalf("no pipeline id: %d", code)
	}
	if r.auditCount(r.tenant, "ci_run.token_refused", "aggregate_no_run_id") != 1 {
		t.Fatal("refusal without a pipeline id not audited")
	}

	// The gate job joins and judges what every job uploaded.
	codeC, c := join(map[string]any{"job_id": "699"}, sha)
	if codeC != http.StatusCreated || c["run_id"] != run {
		t.Fatalf("gate job: %d %v", codeC, c)
	}
	resp, v := r.post("/api/v1/ci/runs/"+run+"/evaluate", c["token"].(string), map[string]int{"scan_failures": 0})
	summary, _ := v["summary"].(map[string]any)
	if resp.StatusCode != http.StatusOK || summary["evaluated"] != float64(2) {
		t.Fatalf("aggregate verdict: %d %v", resp.StatusCode, v)
	}
	if r.auditCount(r.tenant, "ci_run.token_issued", `"joined": true`) < 2 {
		t.Fatal("joins not audited")
	}

	// Evaluated: no job can add results any more, and the next aggregate
	// exchange of the pipeline run opens a new run.
	if c := upload(run, tokA, ciFinding("Late", "late", "high", ctis.FindingTypeVulnerability, "late.go", 1)); c != http.StatusConflict {
		t.Fatalf("upload after the verdict: %d", c)
	}
	if _, o := join(map[string]any{"job_id": "607"}, sha); o["run_id"] == run || o["run_id"] == nil {
		t.Fatalf("an evaluated run was joined: %v", o)
	}

	// A long job renews its token (continuation) without breaking the
	// other jobs' tokens.
	codeD, d := join(map[string]any{"job_id": "801", "pipeline_id": "1004"}, sha)
	codeE, e := join(map[string]any{"job_id": "802", "pipeline_id": "1004"}, sha)
	if codeD != http.StatusCreated || codeE != http.StatusCreated || d["run_id"] != e["run_id"] {
		t.Fatalf("pipeline 1004: %v / %v", d, e)
	}
	run4 := d["run_id"].(string)
	resp, renewed := r.post("/api/v1/ci/oidc/exchange", "", map[string]any{"tenant_id": r.tenant.String(), "run_id": run4,
		"id_token": r.idp.token(t, aud, "acme/api", "main", sha, map[string]any{"job_id": "801", "pipeline_id": "1004"})})
	if resp.StatusCode != http.StatusCreated || renewed["run_id"] != run4 {
		t.Fatalf("continuation: %d %v", resp.StatusCode, renewed)
	}
	for _, tok := range []string{d["token"].(string), e["token"].(string), renewed["token"].(string)} {
		if c := upload(run4, tok, ciFinding("X", "x", "low", ctis.FindingTypeVulnerability, "x.go", 1)); c != http.StatusCreated {
			t.Fatalf("a job token stopped working after a renewal: %d", c)
		}
	}

	// Retention deletes expired job tokens: they stop working.
	if _, err := r.repo.ClearExpiredRunTokens(ctx, r.tenant, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if c := upload(run4, e["token"].(string), ciFinding("Y", "y", "low", ctis.FindingTypeVulnerability, "y.go", 1)); c != http.StatusUnauthorized {
		t.Fatalf("an expired job token still works: %d", c)
	}
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM ci_run_tokens WHERE tenant_id = $1`, r.tenant.String()).Scan(&tokens)
	if tokens != 0 {
		t.Fatalf("%d expired job tokens left", tokens)
	}
}
