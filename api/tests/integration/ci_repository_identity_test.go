package integration

import (
	"context"
	"net/http"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A CI run finds its repository asset by the code host's immutable id, not
// its name. A renamed (or transferred) repository keeps its asset: findings,
// branches and the baseline stay, so its next pull request is still judged
// against them instead of being blocked by an empty new asset. A repository
// that repository import created as "org/repo" is the same asset CI uses.
// Another tenant's asset with the same id is never used.
func TestCIRepositoryIdentityByProviderID(t *testing.T) {
	r := newProviderRig(t)
	ctx := context.Background()
	r.svc.SetRepositoryIdentity(postgres.NewRepositoryIdentityRepository(r.db))
	cfg := r.trustFor(r.tenant, cirun.ProviderGitHub, cirun.GitHubIssuer, cirun.Rules{Owners: []string{"acme"}})
	judge := func(repo, repoID string, over map[string]any, f ...ctis.Finding) (map[string]any, string) {
		t.Helper()
		claims := map[string]any{
			"iss": cirun.GitHubIssuer, "aud": cfg.Audience, "sub": "repo:" + repo + ":ref:refs/heads/main",
			"repository": repo, "repository_id": repoID, "repository_owner": "acme", "repository_owner_id": "77",
			"actor": "dev", "run_attempt": "1", "sha": "1111111111111111111111111111111111111111",
			"workflow_ref": repo + "/.github/workflows/scan.yml@refs/heads/main", "jti": shared.NewID().String(),
		}
		code, ex := r.exchangeWith(r.tenant, r.idp.sign(t, claims, over), nil)
		if code != http.StatusCreated {
			t.Fatalf("exchange %s: %d %v", repo, code, ex)
		}
		run, tok := ex["run_id"].(string), ex["token"].(string)
		if len(f) > 0 {
			if resp, out := r.post("/api/v1/ci/runs/"+run+"/results", tok, ciReport("github.com/"+repo, f...)); resp.StatusCode != http.StatusCreated {
				t.Fatalf("upload: %d %v", resp.StatusCode, out)
			}
		}
		resp, v := r.post("/api/v1/ci/runs/"+run+"/evaluate", tok, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("evaluate: %d %v", resp.StatusCode, v)
		}
		got, err := r.repo.GetRun(ctx, r.tenant, shared.MustIDFromString(run))
		if err != nil {
			t.Fatal(err)
		}
		return v, got.RepositoryAssetID.String()
	}
	push := map[string]any{"ref": "refs/heads/main", "event_name": "push", "run_id": "1"}
	pr := map[string]any{"ref": "refs/pull/9/merge", "head_ref": "fix", "base_ref": "main", "event_name": "pull_request", "run_id": "2"}
	repos := func(tid shared.ID) int {
		t.Helper()
		var n int
		if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM assets WHERE tenant_id = $1 AND asset_type = 'repository'`, tid.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	nameOf := func(id string) string {
		t.Helper()
		var n string
		_ = r.db.QueryRowContext(ctx, `SELECT name FROM assets WHERE id = $1`, id).Scan(&n)
		return n
	}
	vuln := ciFinding("SQL injection", "go.sqli", "high", ctis.FindingTypeVulnerability, "db.go", 7)

	// The default branch has the finding (existing debt).
	_, asset := judge("acme/api", "4242", push, vuln)
	// The repository is renamed: same id, new name. Its pull request still
	// finds the finding pre-existing on main, and runs on the same asset,
	// now named after the repository.
	v, renamed := judge("acme/api-renamed", "4242", pr, vuln)
	if renamed != asset || v["verdict"] != "pass" || repos(r.tenant) != 1 {
		t.Fatalf("rename split the repository: asset %s -> %s, %d assets, verdict %v", asset, renamed, repos(r.tenant), v)
	}
	if nameOf(asset) != "github.com/acme/api-renamed" {
		t.Fatalf("asset name = %q", nameOf(asset))
	}
	// The rename is an audit event, with the old and new name.
	var audited int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'asset.renamed'
		AND resource_id = $2 AND metadata->>'old_name' = 'github.com/acme/api' AND metadata->>'new_name' = 'github.com/acme/api-renamed'`,
		r.tenant.String(), asset).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("rename audited %d times: %v", audited, err)
	}

	// Repository import created "acme/web" with its id: CI uses that asset.
	imported := shared.NewID()
	if _, err := r.db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status)
		VALUES ($1, $2, 'acme/web', 'repository', 'medium', 'active')`, imported.String(), r.tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.db.ExecContext(ctx, `INSERT INTO asset_repositories (asset_id, repo_id, full_name, web_url, visibility)
		VALUES ($1, '5151', 'acme/web', 'https://github.com/acme/web', 'private')
		ON CONFLICT (asset_id) DO UPDATE SET repo_id = '5151', web_url = 'https://github.com/acme/web'`, imported.String()); err != nil {
		t.Fatal(err)
	}
	if _, web := judge("acme/web", "5151", push); web != imported.String() || nameOf(web) != "github.com/acme/web" {
		t.Fatalf("CI made a second asset for an imported repository: %s (%s)", web, nameOf(web))
	}

	// Another tenant's imported asset with an id is never used for this
	// tenant's run: it gets its own asset.
	foreign := shared.NewID()
	if _, err := r.db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status)
		VALUES ($1, $2, 'acme/ops', 'repository', 'medium', 'active')`, foreign.String(), r.other.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.db.ExecContext(ctx, `INSERT INTO asset_repositories (asset_id, repo_id, full_name, web_url, visibility)
		VALUES ($1, '6161', 'acme/ops', 'https://github.com/acme/ops', 'private')
		ON CONFLICT (asset_id) DO UPDATE SET repo_id = '6161', web_url = 'https://github.com/acme/ops'`, foreign.String()); err != nil {
		t.Fatal(err)
	}
	if _, ops := judge("acme/ops", "6161", push); ops == foreign.String() || nameOf(foreign.String()) != "acme/ops" {
		t.Fatal("a run used another tenant's repository asset")
	}
}
