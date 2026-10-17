package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	scmappsvc "github.com/openctemio/openctem/api/internal/app/scmapp"
	"github.com/openctemio/openctem/api/internal/infra/scm/gitlabapi"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/scmapp"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// fakeMRTargets answers a GitLab merge request's target branch for one
// tenant's group, as the organization's GitLab connection would.
type fakeMRTargets struct {
	tenant shared.ID
	host   string
	target string
}

func (f fakeMRTargets) GitLabClientFor(_ context.Context, tid shared.ID, host, project string) (scmappsvc.GitLabAPI, int64, error) {
	if tid != f.tenant || host != f.host || project != "acme/api" {
		return nil, 0, scmapp.ErrNotFound
	}
	return fakeMRAPI{target: f.target}, 9, nil
}

type fakeMRAPI struct{ target string }

func (fakeMRAPI) Token(context.Context) (*gitlabapi.TokenInfo, error)     { return nil, nil }
func (fakeMRAPI) CurrentUser(context.Context) (*gitlabapi.User, error)    { return nil, nil }
func (fakeMRAPI) Group(context.Context, string) (*gitlabapi.Group, error) { return nil, nil }
func (fakeMRAPI) GroupMember(context.Context, int64, int64) (bool, error) { return true, nil }
func (f fakeMRAPI) MergeRequest(_ context.Context, _ string, iid int) (*gitlabapi.MergeRequest, error) {
	return &gitlabapi.MergeRequest{IID: iid, TargetBranch: f.target}, nil
}
func (fakeMRAPI) SetCommitStatus(context.Context, string, string, string, string, string, string, int64) error {
	return nil
}
func (fakeMRAPI) UpsertMergeRequestNote(context.Context, string, int, int64, string, string) error {
	return nil
}

// The gate's baseline is never chosen by the job. A developer pushes
// release/x carrying a vulnerability (a push run records it open there),
// then opens a merge request whose job names release/x as its base: the
// finding must count as new against the default branch, not as
// pre-existing. A GitLab merge request is compared with its target branch
// only when GitLab, read through the organization's connection, says so and
// that branch is protected; a branch name (release/*) never qualifies.
func TestCIBaselineIsVerifiedNeverJobChosen(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	host := strings.ToLower(strings.TrimPrefix(r.idp.srv.URL, "https://"))
	repoName := host + "/acme/api"
	const sha = "5555555555555555555555555555555555555555"

	exchange := func(ref, baseRef, job string) (string, string) {
		t.Helper()
		over := map[string]any{"job_id": job}
		if strings.HasPrefix(ref, "refs/merge-requests/") {
			over["pipeline_source"] = "merge_request_event"
		}
		resp, ex := r.post("/api/v1/ci/oidc/exchange", "", map[string]string{"tenant_id": r.tenant.String(),
			"id_token": r.idp.token(t, cfg.Audience, "acme/api", ref, sha, over), "base_ref": baseRef})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("exchange %s: %d %v", ref, resp.StatusCode, ex)
		}
		return ex["run_id"].(string), ex["token"].(string)
	}
	judge := func(ref, baseRef, job string, f ...ctis.Finding) map[string]any {
		t.Helper()
		run, tok := exchange(ref, baseRef, job)
		if len(f) > 0 {
			if resp, out := r.post("/api/v1/ci/runs/"+run+"/results", tok, ciReport(repoName, f...)); resp.StatusCode != http.StatusCreated {
				t.Fatalf("upload: %d %v", resp.StatusCode, out)
			}
		}
		resp, v := r.post("/api/v1/ci/runs/"+run+"/evaluate", tok, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("evaluate: %d %v", resp.StatusCode, v)
		}
		return v
	}
	baseline := func(v map[string]any) string {
		b, _ := v["baseline"].(map[string]any)
		s, _ := b["branch"].(string)
		return s
	}
	vuln := ciFinding("SQL injection", "go.sqli", "high", ctis.FindingTypeVulnerability, "db.go", 7)

	// The default branch is scanned clean; the developer pushes release/x
	// with the vulnerability.
	judge("main", "", "1", ciFinding("Info", "go.info", "low", ctis.FindingTypeVulnerability, "a.go", 1))
	judge("release/x", "", "2", vuln)
	// A branch named release/* is not exposure: the finding stays
	// branch-only.
	var branchOnly bool
	if err := r.db.QueryRowContext(ctx, `SELECT branch_only FROM findings WHERE tenant_id = $1 AND rule_id = 'go.sqli'`,
		r.tenant.String()).Scan(&branchOnly); err != nil || !branchOnly {
		t.Fatalf("finding from release/x promoted to an organization finding: branch_only=%v %v", branchOnly, err)
	}

	// The exploit: a merge request whose job names release/x as its base.
	// The finding is new against main, and the run fails.
	v := judge("refs/merge-requests/4/head", "release/x", "3", vuln)
	if s, _ := v["summary"].(map[string]any); v["verdict"] != "fail" || s["new"] != float64(1) || baseline(v) != "main" {
		t.Fatalf("job-chosen baseline honored: %v", v)
	}
	// The same with a push run naming a base.
	if v := judge("feature/y", "release/x", "4", vuln); v["verdict"] != "fail" || baseline(v) != "main" {
		t.Fatalf("push run's base hint honored: %v", v)
	}

	// GitLab says the merge request targets release/x, but release/x is not
	// protected: still main.
	r.svc.SetGitLab(fakeMRTargets{tenant: r.tenant, host: host, target: "release/x"})
	if v := judge("refs/merge-requests/5/head", "", "5", vuln); v["verdict"] != "fail" || baseline(v) != "main" {
		t.Fatalf("unprotected target used as the baseline: %v", v)
	}
	// Protected (from the code host or an administrator): the verified
	// target is the baseline, and the finding already there is pre-existing.
	if _, err := r.db.ExecContext(ctx, `UPDATE repository_branches b SET is_protected = TRUE FROM assets a
		WHERE a.id = b.repository_id AND a.tenant_id = $1 AND b.name = 'release/x'`, r.tenant.String()); err != nil {
		t.Fatal(err)
	}
	if v := judge("refs/merge-requests/6/head", "", "6", vuln); v["verdict"] != "pass" || baseline(v) != "release/x" {
		t.Fatalf("verified protected target: %v", v)
	}
	// Even a protected branch is never taken from the job: without the
	// connection the merge request is compared with main again.
	r.svc.SetGitLab(nil)
	if v := judge("refs/merge-requests/7/head", "release/x", "7", vuln); v["verdict"] != "fail" || baseline(v) != "main" {
		t.Fatalf("protected branch taken from the job's hint: %v", v)
	}
	// Another tenant's connection is never used for this tenant's run.
	r.svc.SetGitLab(fakeMRTargets{tenant: r.other, host: host, target: "release/x"})
	if v := judge("refs/merge-requests/8/head", "", "8", vuln); baseline(v) != "main" {
		t.Fatalf("another tenant's connection used: %v", v)
	}
}

// A GitHub pull request's signed base_ref is its baseline when that branch is
// protected; an unprotected one (any developer can create release/1) falls
// back to the default branch.
func TestCIGitHubSignedBaseNeedsAProtectedBranch(t *testing.T) {
	r := newProviderRig(t)
	ctx := context.Background()
	cfg := r.trustFor(r.tenant, cirun.ProviderGitHub, cirun.GitHubIssuer, cirun.Rules{Owners: []string{"acme"}})
	base := map[string]any{
		"iss": cirun.GitHubIssuer, "aud": cfg.Audience, "sub": "repo:acme/api:ref:refs/heads/main",
		"repository": "acme/api", "repository_id": "4242", "repository_owner": "acme", "repository_owner_id": "77",
		"actor": "dev", "run_attempt": "1", "sha": "1111111111111111111111111111111111111111",
		"workflow_ref": "acme/api/.github/workflows/scan.yml@refs/heads/main",
	}
	judge := func(over map[string]any, f ...ctis.Finding) map[string]any {
		t.Helper()
		o := map[string]any{"jti": shared.NewID().String()}
		for k, v := range over {
			o[k] = v
		}
		code, ex := r.exchangeWith(r.tenant, r.idp.sign(t, base, o), nil)
		if code != http.StatusCreated {
			t.Fatalf("exchange: %d %v", code, ex)
		}
		run, tok := ex["run_id"].(string), ex["token"].(string)
		if len(f) > 0 {
			if resp, out := r.post("/api/v1/ci/runs/"+run+"/results", tok, ciReport("github.com/acme/api", f...)); resp.StatusCode != http.StatusCreated {
				t.Fatalf("upload: %d %v", resp.StatusCode, out)
			}
		}
		resp, v := r.post("/api/v1/ci/runs/"+run+"/evaluate", tok, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("evaluate: %d %v", resp.StatusCode, v)
		}
		return v
	}
	vuln := ciFinding("SQL injection", "go.sqli", "high", ctis.FindingTypeVulnerability, "db.go", 7)
	push := func(branch, runID string, f ...ctis.Finding) {
		judge(map[string]any{"ref": "refs/heads/" + branch, "event_name": "push", "run_id": runID}, f...)
	}
	pr := func(n, runID string) map[string]any {
		return judge(map[string]any{"ref": "refs/pull/" + n + "/merge", "head_ref": "fix", "base_ref": "release/1",
			"event_name": "pull_request", "run_id": runID}, vuln)
	}
	push("main", "1", ciFinding("Info", "go.info", "low", ctis.FindingTypeVulnerability, "a.go", 1))
	push("release/1", "2", vuln)
	if v := pr("3", "3"); v["verdict"] != "fail" {
		t.Fatalf("unprotected signed base used: %v", v)
	}
	if _, err := r.db.ExecContext(ctx, `UPDATE repository_branches b SET is_protected = TRUE FROM assets a
		WHERE a.id = b.repository_id AND a.tenant_id = $1 AND b.name = 'release/1'`, r.tenant.String()); err != nil {
		t.Fatal(err)
	}
	if v := pr("4", "4"); v["verdict"] != "pass" {
		t.Fatalf("protected signed base not used: %v", v)
	}
}
