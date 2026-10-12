package integration

import (
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
)

// A pull request is compared with its base branch when the repository has
// scanned it and it counts as exposure (a release branch here); a base branch
// that does not count (a feature branch) never becomes the baseline, so the
// job's hint can narrow but not widen what passes (RFC-077 G-5).
func TestCIBaseBranchBaseline(t *testing.T) {
	r := newCIRig(t)
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	aud := cfg.Audience
	host := strings.TrimPrefix(r.idp.srv.URL, "https://")
	repoName := strings.ToLower(host) + "/acme/api"
	const sha = "5555555555555555555555555555555555555555"

	exchange := func(ref, baseRef, job string) (string, string) {
		t.Helper()
		resp, ex := r.post("/api/v1/ci/oidc/exchange", "", map[string]string{"tenant_id": r.tenant.String(),
			"id_token": r.idp.token(t, aud, "acme/api", ref, sha, map[string]any{"job_id": job}), "base_ref": baseRef})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("exchange %s: %d %v", ref, resp.StatusCode, ex)
		}
		return ex["run_id"].(string), ex["token"].(string)
	}
	upload := func(run, tok string, f ctis.Finding) {
		t.Helper()
		if resp, out := r.post("/api/v1/ci/runs/"+run+"/results", tok, ciReport(repoName, f)); resp.StatusCode != http.StatusCreated {
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
	onRelease := ciFinding("Old SQLi", "go.sqli", "high", ctis.FindingTypeVulnerability, "db.go", 7)
	onFeature := ciFinding("Feature SQLi", "go.sqli", "high", ctis.FindingTypeVulnerability, "api.go", 9)

	// The default branch is scanned clean; release/1 and feature/x carry a finding.
	run, tok := exchange("main", "", "1")
	evaluate(run, tok)
	run, tok = exchange("release/1", "", "2")
	upload(run, tok, onRelease)
	evaluate(run, tok)
	run, tok = exchange("feature/x", "", "3")
	upload(run, tok, onFeature)
	evaluate(run, tok)

	// A pull request into release/1 that still has the release finding: it is
	// pre-existing there, so it passes.
	run, tok = exchange("fix/a", "release/1", "4")
	upload(run, tok, onRelease)
	v := evaluate(run, tok)
	base, _ := v["baseline"].(map[string]any)
	if v["verdict"] != "pass" || base["branch"] != "release/1" {
		t.Fatalf("pull request into release/1: %v", v)
	}
	// Into feature/x (not exposure): compared with main instead, so the
	// finding is new and fails.
	run, tok = exchange("fix/b", "feature/x", "5")
	upload(run, tok, onFeature)
	v = evaluate(run, tok)
	base, _ = v["baseline"].(map[string]any)
	if v["verdict"] != "fail" || base["branch"] != "main" {
		t.Fatalf("pull request into feature/x: %v", v)
	}
	// The run records the base branch it was given.
	var recorded string
	if err := r.db.QueryRow(`SELECT base_ref FROM ci_runs WHERE id = $1`, run).Scan(&recorded); err != nil || recorded != "feature/x" {
		t.Fatalf("base_ref = %q %v", recorded, err)
	}
}
