package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func provExec(ctx context.Context, t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(ctx, q, args...); err != nil {
		t.Fatalf("fixture: %v\n%s", err, q)
	}
}

// provenanceFixture: a repository with main and a feature branch, one
// finding seen on both, and two CI runs that reported it.
func provenanceFixture(ctx context.Context, t *testing.T, db *sql.DB, tenant shared.ID) (finding shared.ID, fp string) {
	t.Helper()
	repo, main, feat := shared.NewID(), shared.NewID(), shared.NewID()
	provExec(ctx, t, db, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'repository')`,
		repo.String(), tenant.String(), "repo-"+repo.String())
	provExec(ctx, t, db, `INSERT INTO asset_repositories (asset_id) VALUES ($1)`, repo.String())
	provExec(ctx, t, db, `INSERT INTO repository_branches (id, repository_id, name, branch_type, is_default) VALUES ($1, $2, 'main', 'main', true), ($3, $2, 'feat/x', 'feature', false)`,
		main.String(), repo.String(), feat.String())
	finding = shared.NewID()
	fp = "fp-" + finding.String()
	provExec(ctx, t, db, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1, $2, $3, 'sca', 'trivy', 'm', 'high', $4, 'new')`, finding.String(), tenant.String(), repo.String(), fp)
	provExec(ctx, t, db, `INSERT INTO finding_branch_occurrences (tenant_id, finding_id, branch_id, repository_id, first_commit_sha, last_commit_sha, last_seen_at)
		VALUES ($1, $2, $3, $4, 'aaa', 'bbb', NOW() - interval '1 hour'), ($1, $2, $5, $4, 'ccc', 'ccc', NOW())`,
		tenant.String(), finding.String(), main.String(), repo.String(), feat.String())
	for i, created := range []string{"NOW() - interval '2 days'", "NOW()"} {
		run := shared.NewID()
		provExec(ctx, t, db, `INSERT INTO ci_runs (id, tenant_id, repository_asset_id, provider, issuer, repository, branch, commit_sha, pull_request, pipeline_url, external_run_id, created_at)
			VALUES ($1, $2, $3, 'gitlab', 'https://gitlab.com', 'gitlab.com/acme/app', 'main', $4, $5, 'https://gitlab.com/acme/app/-/pipelines/1', $6, `+created+`)`,
			run.String(), tenant.String(), repo.String(), []string{"aaa", "bbb"}[i], []string{"7", ""}[i], []string{"1", "2"}[i])
		provExec(ctx, t, db, `INSERT INTO ci_run_findings (tenant_id, run_id, fingerprint) VALUES ($1, $2, $3)`, tenant.String(), run.String(), fp)
	}
	return finding, fp
}

func TestFindingProvenance_BranchesAndRunsTenantScoped(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewFindingRepository(&DB{DB: db})
	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	finding, fp := provenanceFixture(ctx, t, db, tenant)

	branches, err := repo.ListFindingBranches(ctx, tenant, finding, 20)
	if err != nil || len(branches) != 2 || branches[0].Name != "main" || !branches[0].IsDefault || branches[0].LastCommit != "bbb" {
		t.Fatalf("branches = %+v (%v)", branches, err)
	}
	runs, first, err := repo.ListFindingRuns(ctx, tenant, fp, 5)
	if err != nil || len(runs) != 2 || runs[0].ExternalRunID != "2" || first == nil || first.ExternalRunID != "1" || first.PullRequest != "7" {
		t.Fatalf("runs = %+v first = %+v (%v)", runs, first, err)
	}

	// Another tenant reads nothing, by id or by fingerprint.
	if b, err := repo.ListFindingBranches(ctx, other, finding, 20); err != nil || len(b) != 0 {
		t.Fatalf("cross-tenant branches = %v (%v)", b, err)
	}
	if r, f, err := repo.ListFindingRuns(ctx, other, fp, 5); err != nil || len(r) != 0 || f != nil {
		t.Fatalf("cross-tenant runs = %v %v (%v)", r, f, err)
	}
}

// A re-sighting moves last_seen_branch/commit to the latest scan's; before,
// the enrich path kept the first sighting's forever.
func TestEnrichBatch_MovesLastSeenBranchAndCommit(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewFindingRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	asset := seedTestAsset(ctx, t, db, tenant)

	first, err := vulnerability.NewFinding(tenant, asset, vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityHigh, "m")
	if err != nil {
		t.Fatal(err)
	}
	first.SetFingerprint("fp-last-seen-" + shared.NewID().String())
	first.SetBranchInfo("main", "67da69d")
	if err := repo.Create(ctx, first); err != nil {
		t.Fatalf("create: %v", err)
	}
	again, _ := vulnerability.NewFinding(tenant, asset, vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityHigh, "m")
	again.SetFingerprint(first.Fingerprint())
	again.SetBranchInfo("feat/bump", "a481d52")
	if _, err := repo.EnrichBatchByFingerprints(ctx, tenant, []*vulnerability.Finding{again}, "scan-2"); err != nil {
		t.Fatalf("enrich: %v", err)
	}
	var branch, commit string
	var seen time.Time
	if err := db.QueryRowContext(ctx, `SELECT last_seen_branch, last_seen_commit, last_seen_at FROM findings WHERE id = $1 AND tenant_id = $2`,
		first.ID().String(), tenant.String()).Scan(&branch, &commit, &seen); err != nil {
		t.Fatal(err)
	}
	if branch != "feat/bump" || commit != "a481d52" {
		t.Fatalf("last seen = %s@%s, want feat/bump@a481d52", branch, commit)
	}
}
