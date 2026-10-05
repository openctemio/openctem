package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Coverage, alert state and stale sources against the real schema
// (migration 001082): observations from pipeline runs and daemon scans
// through the tool catalog, expectations and alert state tenant-scoped,
// stale marking and retirement touching only findings this pipeline alone
// reported. Requires DATABASE_URL.
func TestCICoverageRepository(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewCIRunRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	now := time.Now().UTC().Truncate(time.Second)

	newRepoAsset := func(tid shared.ID, name string) shared.ID {
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, criticality)
			VALUES ($1, $2, $3, 'repository', 'high')`, id.String(), tid.String(), name+"-"+id.String()[:8]); err != nil {
			t.Fatal(err)
		}
		return id
	}
	repoA := newRepoAsset(tenant, "github.com/acme/api")
	repoB := newRepoAsset(tenant, "github.com/acme/web")
	otherRepo := newRepoAsset(other, "github.com/other/api")

	pipe := func(tid, asset shared.ID, ext string) *cirun.Pipeline {
		p, _, err := repo.UpsertPipeline(ctx, &cirun.Pipeline{ID: shared.NewID(), TenantID: tid, Provider: cirun.ProviderGitHub,
			Issuer: cirun.GitHubIssuer, ExternalRepoID: ext, WorkflowPath: ".github/workflows/scan.yml", RepositoryAssetID: asset,
			RepositoryName: "github.com/acme/x", CreatedAt: now}, false, cirun.PipelineCaps{})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	pA, pB := pipe(tenant, repoA, "1"), pipe(tenant, repoB, "2")
	pOther := pipe(other, otherRepo, "1")

	run := func(tid shared.ID, p *cirun.Pipeline, at time.Time, tools string, fps ...string) shared.ID {
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO ci_runs (id, tenant_id, repository_asset_id, provider, issuer,
			repository, branch, is_default_branch, status, created_at, pipeline_id, tools)
			VALUES ($1, $2, $3, 'github', $4, 'github.com/acme/x', 'main', TRUE, 'evaluated', $5, $6, $7::jsonb)`,
			id.String(), tid.String(), p.RepositoryAssetID.String(), cirun.GitHubIssuer, at, p.ID.String(), tools); err != nil {
			t.Fatal(err)
		}
		for _, fp := range fps {
			if _, err := db.ExecContext(ctx, `INSERT INTO ci_run_findings (tenant_id, run_id, fingerprint) VALUES ($1, $2, $3)`,
				tid.String(), id.String(), fp); err != nil {
				t.Fatal(err)
			}
		}
		if err := repo.RefreshPipeline(ctx, tid, p.ID); err != nil {
			t.Fatal(err)
		}
		return id
	}
	lastA := now.Add(-20 * 24 * time.Hour)
	run(tenant, pA, lastA, `[{"name":"semgrep"},{"name":"gitleaks"},{"name":"unknown-tool"}]`, "fp-only-a", "fp-shared", "fp-seen-later")
	run(tenant, pB, now.Add(-time.Hour), `[{"name":"trivy"}]`, "fp-shared")
	run(other, pOther, now, `[{"name":"semgrep"}]`, "fp-only-a")

	// A daemon scan of repository B with checkov (iac).
	if _, err := db.ExecContext(ctx, `INSERT INTO scan_sessions (tenant_id, scanner_name, asset_type, asset_value, asset_id,
		status, completed_at) VALUES ($1, 'checkov', 'repository', 'github.com/acme/web', $2, 'completed', $3)`,
		tenant.String(), repoB.String(), now.Add(-2*24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	obs, err := repo.CoverageObservations(ctx, tenant, now.Add(-90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// The newest observation per repository, capability and source kind.
	got := map[string]int{}
	for _, o := range obs {
		if o.RepositoryAssetID == otherRepo {
			t.Fatal("another tenant's run observed")
		}
		got[o.RepositoryAssetID.String()+"/"+string(o.Capability)+"/"+o.SourceKind]++
	}
	want := []string{
		repoA.String() + "/sast/" + cirun.SourcePipeline, repoA.String() + "/secrets/" + cirun.SourcePipeline,
		// trivy reports sca and iac; checkov (a daemon scan) iac.
		repoB.String() + "/sca/" + cirun.SourcePipeline, repoB.String() + "/iac/" + cirun.SourcePipeline,
		repoB.String() + "/iac/" + cirun.SourceScan,
	}
	for _, k := range want {
		if got[k] != 1 {
			t.Fatalf("observation %s = %d, want 1 (all: %v)", k, got[k], got)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("observations = %v", got)
	}
	repos, err := repo.ListRepositories(ctx, tenant, nil, 100)
	if err != nil || len(repos) != 2 {
		t.Fatalf("repositories = %d %v", len(repos), err)
	}

	// Expectations: tenant-scoped, upsert, delete.
	if err := repo.UpsertExpectation(ctx, &cirun.Expectation{TenantID: tenant, RepositoryAssetID: repoA,
		Capabilities: []cirun.Capability{cirun.CapabilitySCA}, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpsertExpectation(ctx, &cirun.Expectation{TenantID: tenant, RepositoryAssetID: otherRepo, UpdatedAt: now}); err == nil {
		t.Fatal("expectation on another tenant's repository stored")
	}
	exps, _ := repo.ListExpectations(ctx, tenant)
	if len(exps) != 1 || exps[repoA].Capabilities[0] != cirun.CapabilitySCA {
		t.Fatalf("expectations = %+v", exps)
	}
	if e, _ := repo.ListExpectations(ctx, other); len(e) != 0 {
		t.Fatal("another tenant sees the expectation")
	}
	if err := repo.DeleteExpectation(ctx, other, repoA); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}
	if ok, _ := repo.RepositoryExists(ctx, tenant, otherRepo); ok {
		t.Fatal("another tenant's repository exists")
	}

	// Alert state: fired once, then not again until cleared.
	al := cirun.Alert{Kind: cirun.AlertScheduleMissed, SubjectID: pA.ID, Detail: map[string]any{"x": 1}}
	if fired, err := repo.FireAlert(ctx, tenant, al, now); err != nil || !fired {
		t.Fatalf("first fire: %v %v", fired, err)
	}
	if fired, _ := repo.FireAlert(ctx, tenant, al, now); fired {
		t.Fatal("alert fired twice")
	}
	if st, _ := repo.ListAlertState(ctx, other); len(st) != 0 {
		t.Fatal("another tenant sees the alert state")
	}
	if err := repo.ClearAlert(ctx, tenant, pA.ID, cirun.AlertScheduleMissed); err != nil {
		t.Fatal(err)
	}
	if fired, _ := repo.FireAlert(ctx, tenant, al, now); !fired {
		t.Fatal("alert not fired again after it cleared")
	}
	if ts, err := repo.PipelineTenantsForPlatform(ctx); err != nil || len(ts) < 2 {
		t.Fatalf("tenants = %v %v", ts, err)
	}

	// Findings on repository A: one only pipeline A reported, one pipeline B
	// also reported, one another source saw after A's last run, one manual.
	finding := func(tid, asset shared.ID, fp, source string, lastSeen time.Time) shared.ID {
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO findings (id, tenant_id, asset_id, fingerprint, source, tool_name,
			title, message, severity, status, last_seen_at) VALUES ($1, $2, $3, $4, $5, 'semgrep', 't', 'm', 'high', 'open', $6)`,
			id.String(), tid.String(), asset.String(), fp, source, lastSeen); err != nil {
			t.Fatal(err)
		}
		return id
	}
	onlyA := finding(tenant, repoA, "fp-only-a", "sast", lastA)
	shared1 := finding(tenant, repoA, "fp-shared", "sast", lastA)
	seenLater := finding(tenant, repoA, "fp-seen-later", "sast", now)
	manual := finding(tenant, repoA, "fp-only-a-manual", "manual", lastA)
	otherFinding := finding(other, otherRepo, "fp-only-a", "sast", lastA)
	status := func(id shared.ID) (string, string) {
		var st, res string
		_ = db.QueryRowContext(ctx, `SELECT status, COALESCE(resolution, '') FROM findings WHERE id = $1`, id.String()).Scan(&st, &res)
		return st, res
	}

	pA, _ = repo.GetPipeline(ctx, tenant, pA.ID)
	ids, err := repo.MarkStaleSourceFindings(ctx, tenant, pA)
	if err != nil || len(ids) != 1 || ids[0] != onlyA {
		t.Fatalf("stale-source findings = %v %v", ids, err)
	}
	if st, res := status(onlyA); st != "not_observed" || res != "source_stale" {
		t.Fatalf("only-A finding = %s/%s", st, res)
	}
	for _, id := range []shared.ID{shared1, seenLater, manual} {
		if st, _ := status(id); st != "open" {
			t.Fatalf("finding %v with another source changed to %s", id, st)
		}
	}
	if st, _ := status(otherFinding); st != "open" {
		t.Fatal("another tenant's finding changed")
	}
	// Idempotent.
	if again, _ := repo.MarkStaleSourceFindings(ctx, tenant, pA); len(again) != 0 {
		t.Fatalf("stale marking repeated: %v", again)
	}

	// Retire: another tenant cannot; the sole finding closes as source
	// retired; others untouched; retiring twice is a conflict.
	if _, _, err := repo.RetirePipeline(ctx, other, pA.ID, nil, "not mine at all", now); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant retire: %v", err)
	}
	_, closed, err := repo.RetirePipeline(ctx, tenant, pA.ID, nil, "workflow deleted from the repository", now)
	if err != nil || len(closed) != 1 || closed[0] != onlyA {
		t.Fatalf("retire = %v %v", closed, err)
	}
	if st, res := status(onlyA); st != "resolved" || res != "source_retired" {
		t.Fatalf("retired-source finding = %s/%s", st, res)
	}
	if st, _ := status(shared1); st != "open" {
		t.Fatal("a finding another pipeline reports was closed")
	}
	if _, _, err := repo.RetirePipeline(ctx, tenant, pA.ID, nil, "workflow deleted again", now); !errors.Is(err, cirun.ErrPipelineRetired) {
		t.Fatalf("second retire: %v", err)
	}
	if got, _ := repo.GetPipeline(ctx, tenant, pA.ID); got.RetiredAt == nil || got.Assess(now, cirun.StatusPolicy{}).Status != cirun.PipelineRetired {
		t.Fatal("pipeline not retired")
	}
	// The next verified run revives it.
	pipe(tenant, repoA, "1")
	if got, _ := repo.GetPipeline(ctx, tenant, pA.ID); got.RetiredAt != nil {
		t.Fatal("a verified run did not revive the retired pipeline")
	}
}
