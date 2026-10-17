package integration

import (
	"context"
	"net/http"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A GitHub pull request records its results on its own scope ("pull/<n>"),
// never on its head branch's name. A head branch may be named like a real
// branch of the repository (a fork's "main" in a private repository that
// sends tokens to fork pull requests, or "release/1.x" into main): recording
// there made the pull request's findings occurrences of that real branch, so a
// later pull request carrying the same finding passed as "pre-existing".
func TestCIPullRequestResultsNeverPoisonARealBranch(t *testing.T) {
	r := newProviderRig(t)
	ctx := context.Background()
	cfg := r.trustFor(r.tenant, cirun.ProviderGitHub, cirun.GitHubIssuer, cirun.Rules{Owners: []string{"acme"}})
	base := map[string]any{
		"iss": cirun.GitHubIssuer, "aud": cfg.Audience, "sub": "repo:acme/api:ref:refs/heads/main",
		"repository": "acme/api", "repository_id": "4242", "repository_owner": "acme", "repository_owner_id": "77",
		"actor": "dev", "run_attempt": "1", "workflow_ref": "acme/api/.github/workflows/scan.yml@refs/heads/main",
		"job_workflow_ref": "acme/api/.github/workflows/scan.yml@refs/heads/main",
	}
	const (
		shaMain = "1111111111111111111111111111111111111111"
		shaPR   = "2222222222222222222222222222222222222222"
	)
	exchange := func(over map[string]any) (string, string) {
		t.Helper()
		o := map[string]any{"jti": shared.NewID().String()}
		for k, v := range over {
			o[k] = v
		}
		code, ex := r.exchangeWith(r.tenant, r.idp.sign(t, base, o), nil)
		if code != http.StatusCreated {
			t.Fatalf("exchange %v: %d %v", over, code, ex)
		}
		return ex["run_id"].(string), ex["token"].(string)
	}
	upload := func(run, tok string, f ...ctis.Finding) {
		t.Helper()
		if resp, out := r.post("/api/v1/ci/runs/"+run+"/results", tok, ciReport("github.com/acme/api", f...)); resp.StatusCode != http.StatusCreated {
			t.Fatalf("upload: %d %v", resp.StatusCode, out)
		}
	}
	evaluate := func(run, tok string) map[string]any {
		t.Helper()
		resp, v := r.post("/api/v1/ci/runs/"+run+"/evaluate", tok, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("evaluate: %d %v", resp.StatusCode, v)
		}
		return v
	}
	pullRequest := func(n, headRef, runID string) map[string]any {
		return map[string]any{"ref": "refs/pull/" + n + "/merge", "head_ref": headRef, "base_ref": "main",
			"event_name": "pull_request", "sha": shaPR, "run_id": runID}
	}
	// occurrences counts open occurrences on a named branch of the repository.
	occurrences := func(branch string) int {
		t.Helper()
		var n int
		if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM finding_branch_occurrences o
			JOIN repository_branches b ON b.id = o.branch_id
			JOIN assets a ON a.id = b.repository_id
			WHERE a.tenant_id = $1 AND a.name = 'github.com/acme/api' AND b.name = $2 AND o.status = 'open'`,
			r.tenant.String(), branch).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	vuln := ciFinding("SQL injection", "go.sqli", "high", ctis.FindingTypeVulnerability, "db.go", 7)

	// The default branch is scanned clean: the baseline.
	run, tok := exchange(map[string]any{"ref": "refs/heads/main", "event_name": "push", "sha": shaMain, "run_id": "1"})
	evaluate(run, tok)
	// A release branch exists and is scanned clean.
	run, tok = exchange(map[string]any{"ref": "refs/heads/release/1.x", "event_name": "push", "sha": shaMain, "run_id": "2"})
	evaluate(run, tok)

	// Pull request #5 whose head branch is named "main" (a fork's main) and
	// #6 from "release/1.x" each carry the finding. Both fail, and neither
	// writes into the real branch of that name.
	for n, head := range map[string]string{"5": "main", "6": "release/1.x"} {
		run, tok = exchange(pullRequest(n, head, "1"+n))
		upload(run, tok, vuln)
		if v := evaluate(run, tok); v["verdict"] != "fail" {
			t.Fatalf("pull request #%s from %s: %v", n, head, v)
		}
		got, err := r.repo.GetRun(ctx, r.tenant, shared.MustIDFromString(run))
		if err != nil || got.Branch != "pull/"+n {
			t.Fatalf("pull request #%s recorded on %q (%v)", n, got.Branch, err)
		}
		if c := occurrences("pull/" + n); c != 1 {
			t.Fatalf("pull request #%s: %d occurrences on its own scope", n, c)
		}
	}
	if c := occurrences("main"); c != 0 {
		t.Fatalf("pull requests wrote %d occurrences into main", c)
	}
	if c := occurrences("release/1.x"); c != 0 {
		t.Fatalf("pull requests wrote %d occurrences into release/1.x", c)
	}

	// A later pull request with the same finding is still judged against a
	// clean main: the finding is new, and it fails.
	run, tok = exchange(pullRequest("7", "feature/x", "17"))
	upload(run, tok, vuln)
	v := evaluate(run, tok)
	if s, _ := v["summary"].(map[string]any); v["verdict"] != "fail" || s["new"] != float64(1) {
		t.Fatalf("later pull request whitewashed by an earlier one: %v", v)
	}
}
