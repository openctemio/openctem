package integration

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The duplicate repository merge: a repository renamed after CI ran (CI then
// made a second asset while the first kept the findings, branches, gate
// policy and coverage expectation), and a repository that import named
// "org/repo" while CI named it "github.com/org/repo", each become one asset
// again. A dry run changes nothing and reports counts; the merge is
// idempotent and never touches another tenant or an unrelated repository.
func TestMergeDuplicateRepositories(t *testing.T) {
	r := newProviderRig(t)
	ctx := context.Background()
	cfg := r.trustFor(r.tenant, cirun.ProviderGitHub, cirun.GitHubIssuer, cirun.Rules{Owners: []string{"acme"}})
	exchange := func(repo, repoID string, f ...ctis.Finding) string {
		t.Helper()
		claims := map[string]any{
			"iss": cirun.GitHubIssuer, "aud": cfg.Audience, "sub": "repo:" + repo + ":ref:refs/heads/main",
			"repository": repo, "repository_id": repoID, "repository_owner": "acme", "repository_owner_id": "77",
			"actor": "dev", "run_attempt": "1", "sha": "1111111111111111111111111111111111111111",
			"workflow_ref": repo + "/.github/workflows/scan.yml@refs/heads/main", "jti": shared.NewID().String(),
			"ref": "refs/heads/main", "event_name": "push", "run_id": "1",
		}
		code, ex := r.exchangeWith(r.tenant, r.idp.sign(t, claims, nil), nil)
		if code != http.StatusCreated {
			t.Fatalf("exchange %s: %d %v", repo, code, ex)
		}
		run, tok := ex["run_id"].(string), ex["token"].(string)
		if resp, out := r.post("/api/v1/ci/runs/"+run+"/results", tok, ciReport("github.com/"+repo, f...)); resp.StatusCode != http.StatusCreated {
			t.Fatalf("upload: %d %v", resp.StatusCode, out)
		}
		got, err := r.repo.GetRun(ctx, r.tenant, shared.MustIDFromString(run))
		if err != nil {
			t.Fatal(err)
		}
		return got.RepositoryAssetID.String()
	}
	q := func(query string, args ...any) int {
		t.Helper()
		var n int
		if err := r.db.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		return n
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := r.db.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	repos := func(tid shared.ID) int {
		return q(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND asset_type = 'repository'`, tid.String())
	}
	vuln := ciFinding("SQL injection", "go.sqli", "high", ctis.FindingTypeVulnerability, "db.go", 7)
	other := ciFinding("XSS", "js.xss", "high", ctis.FindingTypeVulnerability, "ui.js", 3)

	// 1. CI ran on acme/api, which has a gate policy and an expectation, then
	// the repository was renamed: CI made a second asset (name lookup).
	oldAPI := exchange("acme/api", "4242", vuln)
	oldID := shared.MustIDFromString(oldAPI)
	if _, err := r.svc.CreateGatePolicy(ctx, r.tenant, cirunapp.GatePolicyInput{ScopeType: cirun.ScopeRepository,
		ScopeID: &oldID, Mode: cirun.ModeEnforce}, cirunapp.Actor{Email: "admin@acme.test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.SetExpectation(ctx, r.tenant, oldID, []string{"sast"}, cirunapp.Actor{Email: "admin@acme.test"}); err != nil {
		t.Fatal(err)
	}
	newAPI := exchange("acme/api-renamed", "4242", vuln)
	// 2. Import named a repository "acme/web" with its id; CI then made
	// "github.com/acme/web".
	imported := shared.NewID()
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status, created_at)
		VALUES ($1, $2, 'acme/web', 'repository', 'medium', 'active', NOW() - interval '1 day')`, imported.String(), r.tenant.String())
	exec(`INSERT INTO asset_repositories (asset_id, repo_id, full_name, web_url, visibility)
		VALUES ($1, '5151', 'acme/web', 'https://github.com/acme/web', 'private')
		ON CONFLICT (asset_id) DO UPDATE SET repo_id = '5151', web_url = 'https://github.com/acme/web'`, imported.String())
	ciWeb := exchange("acme/web", "5151", other)
	// 3. An unrelated repository, and the same names in another tenant.
	exchange("acme/lib", "6161")
	foreign := shared.NewID()
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status) VALUES ($1, $2, 'acme/web', 'repository', 'medium', 'active')`,
		foreign.String(), r.other.String())
	exec(`INSERT INTO asset_repositories (asset_id, repo_id, full_name, web_url, visibility)
		VALUES ($1, '5151', 'acme/web', 'https://github.com/acme/web', 'private')
		ON CONFLICT (asset_id) DO UPDATE SET repo_id = '5151', web_url = 'https://github.com/acme/web'`, foreign.String())
	foreignCI := shared.NewID()
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status) VALUES ($1, $2, 'github.com/acme/web', 'repository', 'medium', 'active')`,
		foreignCI.String(), r.other.String())
	if repos(r.tenant) != 5 || oldAPI == newAPI {
		t.Fatalf("setup: %d repositories", repos(r.tenant))
	}

	m := postgres.NewRepositoryMergeRepository(r.db)
	// Dry run: counts, no change.
	dry, err := m.MergeDuplicateRepositories(ctx, r.tenant, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if dry.Groups != 2 || dry.AssetsMerged != 2 || dry.Pipelines != 2 || repos(r.tenant) != 5 {
		t.Fatalf("dry run: %+v, %d repositories", dry, repos(r.tenant))
	}

	rep, err := m.MergeDuplicateRepositories(ctx, r.tenant, true, false)
	if err != nil || rep.Groups != 2 || rep.FailedGroups != 0 {
		t.Fatalf("merge: %+v %v", rep, err)
	}
	if repos(r.tenant) != 3 {
		t.Fatalf("after merge: %d repositories", repos(r.tenant))
	}
	// The renamed repository is the old asset with the new name; its
	// pipeline, findings, policy and expectation are all on it.
	if q(`SELECT count(*) FROM assets WHERE id = $1 AND name = 'github.com/acme/api-renamed'`, oldAPI) != 1 ||
		q(`SELECT count(*) FROM assets WHERE id = $1`, newAPI) != 0 {
		t.Fatal("renamed repository not merged into the old asset under the new name")
	}
	if q(`SELECT count(*) FROM ci_pipelines WHERE tenant_id = $1 AND repository_asset_id = $2`, r.tenant.String(), oldAPI) != 1 ||
		q(`SELECT count(*) FROM ci_gate_policies WHERE tenant_id = $1 AND repository_asset_id = $2`, r.tenant.String(), oldAPI) != 1 ||
		q(`SELECT count(*) FROM ci_coverage_expectations WHERE tenant_id = $1 AND repository_asset_id = $2`, r.tenant.String(), oldAPI) != 1 ||
		q(`SELECT count(*) FROM findings WHERE tenant_id = $1 AND asset_id = $2`, r.tenant.String(), oldAPI) < 1 {
		t.Fatal("the renamed repository's pipeline, policy, expectation or findings did not move")
	}
	// The imported repository (older) keeps the CI one's findings and takes
	// the host/path name.
	if q(`SELECT count(*) FROM assets WHERE id = $1 AND name = 'github.com/acme/web'`, imported.String()) != 1 ||
		q(`SELECT count(*) FROM assets WHERE id = $1`, ciWeb) != 0 ||
		q(`SELECT count(*) FROM findings WHERE tenant_id = $1 AND asset_id = $2 AND rule_id = 'js.xss'`, r.tenant.String(), imported.String()) != 1 {
		t.Fatal("imported and CI repository not merged")
	}
	// Idempotent; the other tenant is untouched.
	again, err := m.MergeDuplicateRepositories(ctx, r.tenant, true, false)
	if err != nil || again.Groups != 0 {
		t.Fatalf("second merge: %+v %v", again, err)
	}
	if repos(r.other) != 2 {
		t.Fatalf("another tenant changed: %d repositories", repos(r.other))
	}
}

// A repository whose duplicate assets carry several gate policies is not
// merged unless asked to resolve it, and then keeps the strictest policy; when
// the policies are stricter on different settings it is never merged. A row
// written onto a duplicate while the merge runs waits for it and is moved,
// never lost to the merged asset's delete.
func TestMergeDuplicateRepositoriesPoliciesAndConcurrentWrites(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := r.db.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	// pair creates "acme/<n>" imported with id <id> (older) and the CI
	// duplicate "github.com/acme/<n>".
	pair := func(name, id string) (shared.ID, shared.ID) {
		imported, ci := shared.NewID(), shared.NewID()
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status, created_at)
			VALUES ($1, $2, $3, 'repository', 'medium', 'active', NOW() - interval '1 day')`, imported.String(), r.tenant.String(), "acme/"+name)
		exec(`INSERT INTO asset_repositories (asset_id, repo_id, full_name, web_url, visibility)
			VALUES ($1, $2, $3, $4, 'private')
			ON CONFLICT (asset_id) DO UPDATE SET repo_id = EXCLUDED.repo_id, web_url = EXCLUDED.web_url`,
			imported.String(), id, "acme/"+name, "https://github.com/acme/"+name)
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status)
			VALUES ($1, $2, $3, 'repository', 'medium', 'active')`, ci.String(), r.tenant.String(), "github.com/acme/"+name)
		return imported, ci
	}
	policy := func(asset shared.ID, severity string, newOnly bool) {
		exec(`INSERT INTO ci_gate_policies (id, tenant_id, scope_type, repository_asset_id, enabled, mode, fail_on_severity,
				new_findings_only, fail_on_kev, modes, allow_repo_policy, fixable_only, created_at, updated_at)
			VALUES ($1, $2, 'repository', $3, TRUE, 'enforce', $4, $5, TRUE, '{}', TRUE, FALSE, NOW(), NOW())`,
			shared.NewID().String(), r.tenant.String(), asset.String(), severity, newOnly)
	}
	count := func(query string, args ...any) int {
		t.Helper()
		var n int
		if err := r.db.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	exists := func(id shared.ID) bool { return count(`SELECT count(*) FROM assets WHERE id = $1`, id.String()) == 1 }

	// svc: the CI duplicate's policy (medium) is stricter than the imported
	// one's (high). lib: high + every finding vs low + new only (neither is
	// stricter on everything).
	svcImported, svcCI := pair("svc", "71")
	policy(svcImported, "high", true)
	policy(svcCI, "medium", true)
	libImported, libCI := pair("lib", "72")
	policy(libImported, "high", false)
	policy(libCI, "low", true)

	m := postgres.NewRepositoryMergeRepository(r.db)
	rep, err := m.MergeDuplicateRepositories(ctx, r.tenant, true, false)
	if err != nil || rep.Groups != 0 || rep.RefusedGroups != 2 || !exists(svcCI) || !exists(libCI) {
		t.Fatalf("without resolve: %+v %v", rep, err)
	}
	refused := map[string]string{}
	for _, g := range rep.MergeDetails {
		refused[g.KeepAssetID] = g.Refused
		if g.GatePolicies != 2 {
			t.Fatalf("group policies = %d", g.GatePolicies)
		}
	}
	if refused[svcImported.String()] != postgres.RefusedPolicyConflict || refused[libImported.String()] != postgres.RefusedPolicyIncomparable {
		t.Fatalf("refusals = %v", refused)
	}

	// A finding written onto the svc duplicate while the merge runs: the
	// merge waits for it and moves it.
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	late := shared.NewID()
	if _, err := tx.ExecContext(ctx, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1, $2, $3, 'sast', 'opengrep', 'late', 'high', $4, 'new')`, late.String(), r.tenant.String(), svcCI.String(), "fp-"+late.String()); err != nil {
		t.Fatal(err)
	}
	done := make(chan *postgres.RepositoryMergeReport, 1)
	go func() {
		rep, err := m.MergeDuplicateRepositories(ctx, r.tenant, true, true)
		if err != nil {
			t.Error(err)
		}
		done <- rep
	}()
	time.Sleep(500 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("the merge did not wait for a concurrent write to a duplicate asset")
	default:
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	rep = <-done
	if rep == nil || rep.Groups != 1 || rep.RefusedGroups != 1 || rep.FailedGroups != 0 {
		t.Fatalf("with resolve: %+v", rep)
	}
	if exists(svcCI) || !exists(libCI) {
		t.Fatal("resolve merged the wrong groups")
	}
	if count(`SELECT count(*) FROM findings WHERE id = $1 AND asset_id = $2`, late.String(), svcImported.String()) != 1 {
		t.Fatal("a finding written during the merge was lost")
	}
	// The strictest policy (medium) is the repository's only one.
	if count(`SELECT count(*) FROM ci_gate_policies WHERE tenant_id = $1 AND repository_asset_id = $2 AND fail_on_severity = 'medium'`,
		r.tenant.String(), svcImported.String()) != 1 ||
		count(`SELECT count(*) FROM ci_gate_policies WHERE tenant_id = $1 AND repository_asset_id = $2`, r.tenant.String(), svcImported.String()) != 1 {
		t.Fatal("the merged repository did not keep the strictest gate policy")
	}
}
