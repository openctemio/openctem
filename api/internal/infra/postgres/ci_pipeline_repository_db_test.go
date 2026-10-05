package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CI pipelines against the real schema (migration 001084): legacy adoption,
// the cadence and gate summary from runs (fork runs excluded, one CI run
// counted once), the data scope on the listing, tenant isolation on every
// read and write, the caps, revocation and the tools cap. Requires
// DATABASE_URL.
func TestCIPipelineRepository(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewCIRunRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	repoA := seedTestAsset(ctx, t, db, tenant)
	repoB := seedTestAsset(ctx, t, db, tenant)
	now := time.Now().UTC().Truncate(time.Second)

	newPipeline := func(tid, asset shared.ID, extID, path string) *cirun.Pipeline {
		return &cirun.Pipeline{ID: shared.NewID(), TenantID: tid, Provider: cirun.ProviderGitHub, Issuer: cirun.GitHubIssuer,
			ExternalRepoID: extID, WorkflowPath: path, RepositoryAssetID: asset, RepositoryName: "github.com/acme/api",
			CreatedAt: now}
	}

	// A backfilled legacy row is adopted by the first verified run of the
	// same repository asset and workflow path.
	legacyID := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO ci_pipelines (id, tenant_id, provider, issuer, external_repo_id,
		workflow_path, repository_asset_id) VALUES ($1, $2, 'github', $3, $4, '.github/workflows/scan.yml', $5)`,
		legacyID.String(), tenant.String(), cirun.GitHubIssuer, cirun.LegacyRepoIDPrefix+repoA.String(), repoA.String()); err != nil {
		t.Fatal(err)
	}
	caps := cirun.PipelineCaps{PerTenant: 3}
	p, created, err := repo.UpsertPipeline(ctx, newPipeline(tenant, repoA, "1001", ".github/workflows/scan.yml"), false, caps)
	if err != nil || created || p.ID != legacyID || p.ExternalRepoID != "1001" || p.IsLegacy() {
		t.Fatalf("legacy adoption: %+v created=%v %v", p, created, err)
	}
	// The same key again: the same row, display refreshed.
	again := newPipeline(tenant, repoA, "1001", ".github/workflows/scan.yml")
	again.RepositoryName, again.WorkflowName = "github.com/acme/api-renamed", "Security scan"
	p2, created, err := repo.UpsertPipeline(ctx, again, false, caps)
	if err != nil || created || p2.ID != legacyID || p2.RepositoryName != "github.com/acme/api-renamed" || p2.WorkflowName != "Security scan" {
		t.Fatalf("same key: %+v %v %v", p2, created, err)
	}
	// A fork upsert never changes the display names.
	forkUp := newPipeline(tenant, repoA, "1001", ".github/workflows/scan.yml")
	forkUp.RepositoryName = "github.com/evil/fork"
	if p3, _, _ := repo.UpsertPipeline(ctx, forkUp, true, caps); p3.RepositoryName != "github.com/acme/api-renamed" {
		t.Fatalf("fork upsert renamed the pipeline: %q", p3.RepositoryName)
	}
	// Another tenant with the same key gets its own row; neither sees the
	// other's.
	otherAsset := seedTestAsset(ctx, t, db, other)
	op, created, err := repo.UpsertPipeline(ctx, newPipeline(other, otherAsset, "1001", ".github/workflows/scan.yml"), false, caps)
	if err != nil || !created || op.ID == legacyID {
		t.Fatalf("other tenant: %+v %v", op, err)
	}
	if _, err := repo.GetPipeline(ctx, other, legacyID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	if err := repo.RefreshPipeline(ctx, other, legacyID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant refresh: %v", err)
	}
	// A pipeline cannot point at another tenant's asset.
	if _, _, err := repo.UpsertPipeline(ctx, newPipeline(tenant, otherAsset, "2002", "x.yml"), false, caps); err == nil {
		t.Fatal("pipeline on another tenant's asset stored")
	}

	// Caps: the tenant has 1 pipeline; two more fit, the fourth does not.
	pb, _, err := repo.UpsertPipeline(ctx, newPipeline(tenant, repoB, "1002", ".github/workflows/scan.yml"), false, caps)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.UpsertPipeline(ctx, newPipeline(tenant, repoB, "1002", ".github/workflows/other.yml"), false, caps); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.UpsertPipeline(ctx, newPipeline(tenant, repoB, "1002", ".github/workflows/third.yml"), false, caps); !errors.Is(err, cirun.ErrPipelineCap) {
		t.Fatalf("over the tenant cap: %v", err)
	}
	trust := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO ci_trust_configs (id, tenant_id, name, provider, issuer, audience)
		VALUES ($1, $2, 'gh', 'github', $3, 'aud')`, trust.String(), tenant.String(), cirun.GitHubIssuer); err != nil {
		t.Fatal(err)
	}
	perCfg := newPipeline(tenant, repoB, "1003", "a.yml")
	perCfg.TrustConfigID = &trust
	if _, _, err := repo.UpsertPipeline(ctx, perCfg, false, cirun.PipelineCaps{PerTrustConfig: 1}); err != nil {
		t.Fatal(err)
	}
	perCfg2 := newPipeline(tenant, repoB, "1003", "b.yml")
	perCfg2.TrustConfigID = &trust
	if _, _, err := repo.UpsertPipeline(ctx, perCfg2, false, cirun.PipelineCaps{PerTrustConfig: 1}); !errors.Is(err, cirun.ErrPipelineCap) {
		t.Fatalf("over the trust configuration cap: %v", err)
	}

	// Runs: a schedule every 24h (two jobs per CI run), one push, a fork run.
	addRun := func(pid shared.ID, at time.Time, event, extRun string, fork, def bool, verdict string) shared.ID {
		id := shared.NewID()
		var v any
		if verdict != "" {
			v = verdict
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO ci_runs (id, tenant_id, repository_asset_id, provider, issuer,
			repository, event, external_run_id, fork, is_default_branch, branch, verdict, evaluated_at, status, created_at,
			pipeline_id, sensor_version)
			VALUES ($1, $2, $3, 'github', $4, 'github.com/acme/api', $5, $6, $7, $8, $9, $10::varchar,
			CASE WHEN $10::varchar IS NULL THEN NULL ELSE $11::timestamptz END,
			CASE WHEN $10::varchar IS NULL THEN 'running' ELSE 'evaluated' END, $11, $12, 'v0.9.0')`,
			id.String(), tenant.String(), repoA.String(), cirun.GitHubIssuer, event, extRun, fork, def,
			map[bool]string{true: "main", false: "feature"}[def], v, at, pid.String()); err != nil {
			t.Fatal(err)
		}
		return id
	}
	for i := 5; i >= 1; i-- {
		at := now.Add(-time.Duration(i) * 24 * time.Hour)
		addRun(legacyID, at, "schedule", fmt.Sprintf("s%d", i), false, true, cirun.VerdictPass)
		addRun(legacyID, at.Add(time.Minute), "schedule", fmt.Sprintf("s%d", i), false, true, cirun.VerdictPass)
	}
	addRun(legacyID, now.Add(-2*time.Hour), "pull_request", "pr1", false, false, cirun.VerdictFail)
	forkRun := addRun(legacyID, now.Add(-time.Hour), "pull_request_target", "f1", true, true, cirun.VerdictFail)
	if err := repo.RefreshPipeline(ctx, tenant, legacyID); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetPipeline(ctx, tenant, legacyID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RunsCount != 11 || got.ScheduleInterval != 24*time.Hour || got.LastDefaultVerdict != cirun.VerdictPass ||
		got.LastPRVerdict != cirun.VerdictFail || got.LastForkRunAt == nil || got.SensorVersion != "v0.9.0" {
		t.Fatalf("summary = runs %d, schedule %s, default %q, pr %q, fork %v, version %q", got.RunsCount, got.ScheduleInterval,
			got.LastDefaultVerdict, got.LastPRVerdict, got.LastForkRunAt, got.SensorVersion)
	}
	if got.LastRunAt == nil || got.LastRunAt.Equal(now.Add(-time.Hour)) {
		t.Fatal("a fork run became the pipeline's last run")
	}
	if a := got.Assess(now, cirun.StatusPolicy{}); !a.Scheduled || a.Status != cirun.PipelineFresh {
		t.Fatalf("assessment = %+v", a)
	}
	// Branches and the gate trend leave fork runs out.
	branches, err := repo.PipelineBranches(ctx, tenant, legacyID)
	if err != nil || len(branches) != 2 || branches[0].Branch != "main" || branches[0].Runs != 10 {
		t.Fatalf("branches = %+v %v", branches, err)
	}
	trend, err := repo.PipelineGateTrend(ctx, tenant, legacyID, 50)
	if err != nil || len(trend) != 10 {
		t.Fatalf("trend = %d %v", len(trend), err)
	}
	for _, g := range trend {
		if g.RunID == forkRun {
			t.Fatal("a fork run in the gate trend")
		}
	}
	if b, _ := repo.PipelineBranches(ctx, other, legacyID); len(b) != 0 {
		t.Fatal("another tenant reads the branches")
	}

	// Data scope: a user who may see only repository B lists B's pipelines.
	user := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'scoped')`, user.String(), user.String()+"@ci.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.String()) })
	if _, err := db.ExecContext(ctx, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'primary')`,
		user.String(), tenant.String(), repoB.String()); err != nil {
		t.Fatal(err)
	}
	scoped, err := repo.ListPipelines(ctx, tenant, cirun.PipelineFilter{DataScope: &shared.DataScope{TenantID: tenant, UserID: user}})
	if err != nil {
		t.Fatal(err)
	}
	for _, sp := range scoped {
		if sp.RepositoryAssetID != repoB {
			t.Fatalf("scoped list shows a pipeline on %s", sp.RepositoryAssetID)
		}
	}
	if len(scoped) != 3 {
		t.Fatalf("scoped list = %d", len(scoped))
	}
	if all, _ := repo.ListPipelines(ctx, other, cirun.PipelineFilter{}); len(all) != 1 || all[0].ID != op.ID {
		t.Fatalf("other tenant's list = %+v", all)
	}

	// Tools: sanitized, de-duplicated, capped; another tenant cannot write.
	runID := addRun(pb.ID, now, "push", "t1", false, true, "")
	// One run, no schedule: no cadence yet (not the cap), so the floor applies.
	if err := repo.RefreshPipeline(ctx, tenant, pb.ID); err != nil {
		t.Fatal(err)
	}
	if one, _ := repo.GetPipeline(ctx, tenant, pb.ID); one.ScheduleInterval != 0 || one.MedianInterval != 0 ||
		one.StaleAfter() != cirun.MinStaleAfter {
		t.Fatalf("single-run cadence = schedule %s, median %s", one.ScheduleInterval, one.MedianInterval)
	}
	many := make([]cirun.ToolLabel, 0, 40)
	for i := range 40 {
		many = append(many, cirun.ToolLabel{Name: fmt.Sprintf("Tool-%02d", i), Version: "1.0"})
	}
	if err := repo.RecordRunTools(ctx, tenant, runID, many); err != nil {
		t.Fatal(err)
	}
	run, _ := repo.GetRun(ctx, tenant, runID)
	if len(run.Tools) != cirun.MaxToolsPerRun || run.Tools[0].Name != "tool-00" || run.Tools[0].Version != "v1.0.0" {
		t.Fatalf("tools = %d %+v", len(run.Tools), run.Tools[:1])
	}
	if err := repo.RecordRunTools(ctx, other, runID, many); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant tools: %v", err)
	}
	if err := repo.RecordRunOutcome(ctx, other, runID, 3); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant outcome: %v", err)
	}

	// Revocation: the configuration's pipelines and its running runs' tokens.
	_, hash, _ := cirun.NewToken()
	exp := now.Add(10 * time.Minute)
	live := &cirun.Run{ID: shared.NewID(), TenantID: tenant, TrustConfigID: &trust, RepositoryAssetID: repoB,
		Provider: cirun.ProviderGitHub, Issuer: cirun.GitHubIssuer, Repository: "github.com/acme/web", Status: cirun.StatusRunning,
		TokenHash: hash, TokenExpiresAt: &exp, CreatedAt: now, UpdatedAt: now}
	if err := repo.CreateRun(ctx, live); err != nil {
		t.Fatal(err)
	}
	if n, err := repo.RevokeTrustConfigPipelines(ctx, other, trust, now); err != nil || n != 0 {
		t.Fatalf("cross-tenant revoke: %d %v", n, err)
	}
	if n, err := repo.RevokeTrustConfigPipelines(ctx, tenant, trust, now); err != nil || n != 1 {
		t.Fatalf("revoke: %d %v", n, err)
	}
	if _, err := repo.GetRunByTokenHash(ctx, hash, now); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("a running run's token survived the revocation: %v", err)
	}
}
