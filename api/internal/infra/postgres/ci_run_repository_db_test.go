package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CI runs against the real schema (migration 001077): tenant isolation on
// every read and write, the data scope on the run list, token lookups that
// honor expiry, OIDC replay, the per-run findings cap, overrides by commit
// prefix, and policies through business units. Requires DATABASE_URL.
func TestCIRunRepository(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewCIRunRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	repoA := seedTestAsset(ctx, t, db, tenant)
	repoB := seedTestAsset(ctx, t, db, tenant)
	now := time.Now().UTC()

	newRun := func(tid, asset shared.ID, exp time.Time) (*cirun.Run, string) {
		tok, hash, err := cirun.NewToken()
		if err != nil {
			t.Fatal(err)
		}
		r := &cirun.Run{ID: shared.NewID(), TenantID: tid, RepositoryAssetID: asset, Provider: cirun.ProviderGitHub,
			Issuer: cirun.GitHubIssuer, Repository: "github.com/acme/api", Ref: "refs/heads/main", Branch: "main",
			CommitSHA: "abcdef1234567", Status: cirun.StatusRunning, TokenHash: hash, TokenExpiresAt: &exp,
			CreatedAt: now, UpdatedAt: now}
		if err := repo.CreateRun(ctx, r); err != nil {
			t.Fatalf("create run: %v", err)
		}
		return r, tok
	}
	runA, tokA := newRun(tenant, repoA, now.Add(10*time.Minute))
	runB, _ := newRun(tenant, repoB, now.Add(10*time.Minute))
	_, tokExpired := newRun(tenant, repoA, now.Add(-time.Second))

	// Token lookups: unexpired only.
	if got, err := repo.GetRunByTokenHash(ctx, cirun.HashToken(tokA), now); err != nil || got.ID != runA.ID {
		t.Fatalf("token lookup: %v %v", got, err)
	}
	if _, err := repo.GetRunByTokenHash(ctx, cirun.HashToken(tokExpired), now); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("expired token: %v", err)
	}
	// Cross-tenant: not found, not listed.
	if _, err := repo.GetRun(ctx, other, runA.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	if runs, total, err := repo.ListRuns(ctx, other, cirun.RunFilter{}); err != nil || total != 0 || len(runs) != 0 {
		t.Fatalf("cross-tenant list: %d %v", total, err)
	}
	if err := repo.SaveVerdict(ctx, other, runA.ID, cirun.VerdictPass, []byte(`{}`), now, 0, nil); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant verdict: %v", err)
	}
	// A run cannot point at another tenant's asset (composite foreign key).
	otherAsset := seedTestAsset(ctx, t, db, other)
	tok, hash, _ := cirun.NewToken()
	_ = tok
	bad := &cirun.Run{ID: shared.NewID(), TenantID: tenant, RepositoryAssetID: otherAsset, Provider: cirun.ProviderGitHub,
		Issuer: cirun.GitHubIssuer, Repository: "x", Status: cirun.StatusRunning, TokenHash: hash, CreatedAt: now, UpdatedAt: now}
	if err := repo.CreateRun(ctx, bad); err == nil {
		t.Fatal("run on another tenant's asset stored")
	}

	// The data scope limits the list to the user's assets.
	user := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'scoped')`, user.String(), user.String()+"@ci.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.String()) })
	if _, err := db.ExecContext(ctx, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'primary')`,
		user.String(), tenant.String(), repoB.String()); err != nil {
		t.Fatal(err)
	}
	runs, total, err := repo.ListRuns(ctx, tenant, cirun.RunFilter{DataScope: &shared.DataScope{TenantID: tenant, UserID: user}})
	if err != nil || total != 1 || runs[0].ID != runB.ID {
		t.Fatalf("scoped list: %d %v", total, err)
	}
	if _, total, _ := repo.ListRuns(ctx, tenant, cirun.RunFilter{}); total != 3 {
		t.Fatalf("unrestricted list: %d", total)
	}

	// Replay: a token id is claimed once; the same token (organization and
	// digest) may be counted again up to the bound, nothing else may.
	jti := "jti-" + shared.NewID().String()
	digest := []byte("0123456789abcdef0123456789abcdef")
	planned := shared.NewID()
	claim := cirun.Replay{Issuer: "https://issuer.test", JTI: jti, TenantID: &tenant, TokenSHA256: digest, RunID: &planned,
		ExpiresAt: now.Add(time.Hour)}
	if ok, _, err := repo.ClaimReplay(ctx, claim); err != nil || !ok {
		t.Fatalf("first claim: %v %v", ok, err)
	}
	ok, prior, err := repo.ClaimReplay(ctx, claim)
	if err != nil || ok || prior == nil || prior.RunID == nil || *prior.RunID != planned || prior.TenantID == nil ||
		*prior.TenantID != tenant || prior.Exchanges != 1 || !bytes.Equal(prior.TokenSHA256, digest) {
		t.Fatalf("second claim: %v %+v %v", ok, prior, err)
	}
	otherIss := claim
	otherIss.Issuer = "https://other-issuer.test"
	if ok, _, _ := repo.ClaimReplay(ctx, otherIss); !ok {
		t.Fatal("same id from another issuer refused")
	}
	if rp, _ := repo.ReuseReplay(ctx, claim.Issuer, jti, shared.NewID(), digest, 5); rp != nil {
		t.Fatal("reused from another organization")
	}
	if rp, _ := repo.ReuseReplay(ctx, claim.Issuer, jti, tenant, []byte("other-token-digest-0123456789abc"), 5); rp != nil {
		t.Fatal("reused with another token's digest")
	}
	for want := 2; want <= 5; want++ {
		rp, err := repo.ReuseReplay(ctx, claim.Issuer, jti, tenant, digest, 5)
		if err != nil || rp == nil || rp.Exchanges != want {
			t.Fatalf("reuse %d: %+v %v", want, rp, err)
		}
	}
	if rp, _ := repo.ReuseReplay(ctx, claim.Issuer, jti, tenant, digest, 5); rp != nil {
		t.Fatal("reused past the bound")
	}
	// The recorded run is kept: binding another run does not move it.
	if err := repo.BindReplayRun(ctx, claim.Issuer, jti, tenant, shared.NewID()); err != nil {
		t.Fatal(err)
	}
	if _, prior, _ := repo.ClaimReplay(ctx, claim); prior == nil || prior.RunID == nil || *prior.RunID != planned {
		t.Fatalf("recorded run moved: %+v", prior)
	}

	// The findings cap holds across reports.
	fps := make([]string, 0, 3)
	for i := range 3 {
		fps = append(fps, fmt.Sprintf("fp-%d", i))
	}
	for _, batch := range [][]string{fps, fps[:1]} {
		if err := repo.ReserveRunReport(ctx, tenant, runA.ID); err != nil {
			t.Fatal(err)
		}
		if err := repo.RecordRunReport(ctx, tenant, runA.ID, batch); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := repo.GetRun(ctx, tenant, runA.ID)
	if got.ReportsCount != 2 || got.FindingsCount != 3 {
		t.Fatalf("counts = %d reports, %d findings", got.ReportsCount, got.FindingsCount)
	}
	if err := repo.RecordRunReport(ctx, other, runA.ID, fps); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant report: %v", err)
	}
	if err := repo.ReserveRunReport(ctx, other, runA.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant report slot: %v", err)
	}

	// Overrides: exact commit, expiry, revocation, tenant.
	fullSHA := strings.Repeat("abcdef12", 5)
	o := &cirun.GateOverride{ID: shared.NewID(), TenantID: tenant, RepositoryAssetID: repoA, CommitSHA: fullSHA,
		Reason: "release hotfix", ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err := repo.CreateOverride(ctx, o); err != nil {
		t.Fatal(err)
	}
	if a, err := repo.ActiveOverride(ctx, tenant, repoA, strings.ToUpper(fullSHA), now); err != nil || a == nil || a.ID != o.ID {
		t.Fatalf("active override: %v %v", a, err)
	}
	if a, _ := repo.ActiveOverride(ctx, tenant, repoA, "ffffff1234567", now); a != nil {
		t.Fatal("override matched another commit")
	}
	// A row stored before full ids were required: its prefix no longer covers
	// a commit that shares it.
	if _, err := db.ExecContext(ctx, `UPDATE ci_gate_overrides SET commit_sha = 'abcdef1' WHERE id = $1`, o.ID.String()); err != nil {
		t.Fatal(err)
	}
	if a, _ := repo.ActiveOverride(ctx, tenant, repoA, fullSHA, now); a != nil {
		t.Fatal("an abbreviated override covered a commit by prefix")
	}
	if _, err := db.ExecContext(ctx, `UPDATE ci_gate_overrides SET commit_sha = $2 WHERE id = $1`, o.ID.String(), fullSHA); err != nil {
		t.Fatal(err)
	}
	if a, _ := repo.ActiveOverride(ctx, other, repoA, fullSHA, now); a != nil {
		t.Fatal("override visible to another tenant")
	}
	if a, _ := repo.ActiveOverride(ctx, tenant, repoA, fullSHA, now.Add(2*time.Hour)); a != nil {
		t.Fatal("expired override active")
	}
	if err := repo.RevokeOverride(ctx, other, o.ID, shared.NewID(), now); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant revoke: %v", err)
	}
	if err := repo.RevokeOverride(ctx, tenant, o.ID, shared.ID{}, now); err != nil {
		t.Fatal(err)
	}
	if a, _ := repo.ActiveOverride(ctx, tenant, repoA, fullSHA, now); a != nil {
		t.Fatal("revoked override active")
	}
	if list, _ := repo.ListOverrides(ctx, tenant, nil, &shared.DataScope{TenantID: tenant, UserID: user}); len(list) != 0 {
		t.Fatal("override on an asset outside the scope listed")
	}

	// Policies through a business unit; one per scope.
	bu := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO business_units (id, tenant_id, name) VALUES ($1, $2, 'payments')`, bu.String(), tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO business_unit_assets (id, tenant_id, business_unit_id, asset_id) VALUES ($1, $2, $3, $4)`,
		shared.NewID().String(), tenant.String(), bu.String(), repoA.String()); err != nil {
		t.Fatal(err)
	}
	if ok, _ := repo.BusinessUnitExists(ctx, other, bu); ok {
		t.Fatal("business unit visible to another tenant")
	}
	p := &cirun.GatePolicy{ID: shared.NewID(), TenantID: tenant, ScopeType: cirun.ScopeBusinessUnit, ScopeID: &bu, Enabled: true,
		Mode: cirun.ModeEnforce, FailOnSeverity: "medium", NewFindingsOnly: true, CreatedAt: now}
	if err := repo.CreateGatePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}
	dup := *p
	dup.ID = shared.NewID()
	if err := repo.CreateGatePolicy(ctx, &dup); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate scope: %v", err)
	}
	if ps, _ := repo.GatePoliciesFor(ctx, tenant, repoA); len(ps) != 1 || ps[0].ID != p.ID {
		t.Fatalf("policies for repo A: %+v", ps)
	}
	if ps, _ := repo.GatePoliciesFor(ctx, tenant, repoB); len(ps) != 0 {
		t.Fatalf("policies for repo B: %+v", ps)
	}
	if ps, _ := repo.GatePoliciesFor(ctx, other, repoA); len(ps) != 0 {
		t.Fatal("another tenant's policy applied")
	}
	if err := repo.DeleteGatePolicy(ctx, other, p.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}
}

func TestCITrustConfigRepository(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewCIRunRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	now := time.Now().UTC()
	c := &cirun.TrustConfig{ID: shared.NewID(), TenantID: tenant, Name: "gh", Provider: cirun.ProviderGitHub,
		Issuer: cirun.GitHubIssuer, Audience: cirun.DefaultAudience(tenant), DefaultBranch: "main", Enabled: true,
		Rules: cirun.Rules{Owners: []string{"acme"}, Refs: []string{"main"}}, CreatedAt: now}
	if err := repo.CreateTrustConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	dup := *c
	dup.ID = shared.NewID()
	if err := repo.CreateTrustConfig(ctx, &dup); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	if got, _ := repo.EnabledTrustConfigs(ctx, tenant, cirun.GitHubIssuer); len(got) != 1 || got[0].Rules.Owners[0] != "acme" {
		t.Fatalf("enabled: %+v", got)
	}
	if got, _ := repo.EnabledTrustConfigs(ctx, other, cirun.GitHubIssuer); len(got) != 0 {
		t.Fatal("another tenant's trust used")
	}
	c.Enabled = false
	if err := repo.UpdateTrustConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.EnabledTrustConfigs(ctx, tenant, cirun.GitHubIssuer); len(got) != 0 {
		t.Fatal("disabled configuration used")
	}
	foreign := *c
	foreign.TenantID = other
	if err := repo.UpdateTrustConfig(ctx, &foreign); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant update: %v", err)
	}
	if err := repo.DeleteTrustConfig(ctx, other, c.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}
	if _, err := repo.GetTrustConfig(ctx, other, c.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	if err := repo.DeleteTrustConfig(ctx, tenant, c.ID); err != nil {
		t.Fatal(err)
	}
}

// The report slots and the verdict are checked against the stored run, not
// the snapshot a request authenticated with: concurrent uploads cannot pass
// MaxRunReports, a report cannot land after the verdict, and a verdict
// computed before a report was recorded is refused (ErrRunChanged).
func TestCIRunReportSlotsAndVerdictGuard(t *testing.T) {
	db := openSensorDB(t)
	// Many goroutines, few connections: the race is on the row, not on
	// the pool (and the test must not exhaust the server's connections).
	db.SetMaxOpenConns(8)
	ctx := context.Background()
	repo := NewCIRunRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	asset := seedTestAsset(ctx, t, db, tenant)
	now := time.Now().UTC()
	newRun := func() *cirun.Run {
		_, hash, err := cirun.NewToken()
		if err != nil {
			t.Fatal(err)
		}
		exp := now.Add(10 * time.Minute)
		r := &cirun.Run{ID: shared.NewID(), TenantID: tenant, RepositoryAssetID: asset, Provider: cirun.ProviderGitHub,
			Issuer: cirun.GitHubIssuer, Repository: "github.com/acme/api", Ref: "refs/heads/main", Branch: "main",
			CommitSHA: strings.Repeat("ab", 20), Status: cirun.StatusRunning, TokenHash: hash, TokenExpiresAt: &exp,
			CreatedAt: now, UpdatedAt: now}
		if err := repo.CreateRun(ctx, r); err != nil {
			t.Fatal(err)
		}
		return r
	}

	// Concurrent reservations: exactly MaxRunReports succeed.
	run := newRun()
	var ok, capped atomic.Int32
	var wg sync.WaitGroup
	for range cirun.MaxRunReports + 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch err := repo.ReserveRunReport(ctx, tenant, run.ID); {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, cirun.ErrRunReportCap):
				capped.Add(1)
			default:
				t.Errorf("reserve: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != cirun.MaxRunReports || capped.Load() != 20 {
		t.Fatalf("reserved %d, capped %d; want %d and 20", ok.Load(), capped.Load(), cirun.MaxRunReports)
	}

	// A verdict computed from 0 findings is refused once a report recorded one.
	run = newRun()
	if err := repo.ReserveRunReport(ctx, tenant, run.ID); err != nil {
		t.Fatal(err)
	}
	if err := repo.RecordRunReport(ctx, tenant, run.ID, []string{"fp-late"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveVerdict(ctx, tenant, run.ID, cirun.VerdictPass, []byte(`{}`), now, 0, nil); !errors.Is(err, cirun.ErrRunChanged) {
		t.Fatalf("stale verdict: %v", err)
	}
	if err := repo.SaveVerdict(ctx, tenant, run.ID, cirun.VerdictFail, []byte(`{}`), now, 1, nil); err != nil {
		t.Fatalf("current verdict: %v", err)
	}
	// After the verdict: no slot, no recording, no second verdict.
	if err := repo.ReserveRunReport(ctx, tenant, run.ID); !errors.Is(err, cirun.ErrRunEvaluated) {
		t.Fatalf("slot after the verdict: %v", err)
	}
	if err := repo.RecordRunReport(ctx, tenant, run.ID, []string{"fp-after"}); !errors.Is(err, cirun.ErrRunEvaluated) {
		t.Fatalf("report after the verdict: %v", err)
	}
	if err := repo.SaveVerdict(ctx, tenant, run.ID, cirun.VerdictPass, []byte(`{}`), now, 1, nil); !errors.Is(err, cirun.ErrRunEvaluated) {
		t.Fatalf("second verdict: %v", err)
	}
	got, err := repo.GetRun(ctx, tenant, run.ID)
	if err != nil || got.Verdict != cirun.VerdictFail || got.FindingsCount != 1 {
		t.Fatalf("stored run: %+v %v", got, err)
	}
}

// Repository events change only the tenant's own pipelines of that
// repository id, and the archived flag is set once and clears.
func TestRepositoryLifecyclePipelines(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	lc := NewRepositoryIdentityRepository(&DB{DB: db})
	pipes := NewCIRunRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	asset := seedTestAsset(ctx, t, db, tenant)
	otherAsset := seedTestAsset(ctx, t, db, other)
	ins := func(tid, aid shared.ID) shared.ID {
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO ci_pipelines (id, tenant_id, provider, issuer, external_repo_id, workflow_path, repository_asset_id, repository_name)
			VALUES ($1, $2, 'github', $3, '77', '.github/workflows/a.yml', $4, 'github.com/acme/old')`,
			id.String(), tid.String(), cirun.GitHubIssuer, aid.String()); err != nil {
			t.Fatal(err)
		}
		return id
	}
	mine, theirs := ins(tenant, asset), ins(other, otherAsset)
	name := func(tid, id shared.ID) (string, bool) {
		p, err := pipes.GetPipeline(ctx, tid, id)
		if err != nil {
			t.Fatal(err)
		}
		return p.RepositoryName, p.RepositoryArchivedAt != nil
	}
	if n, err := lc.RenamePipelineRepository(ctx, tenant, "github", cirun.GitHubIssuer, "77", "github.com/acme/new"); err != nil || n != 1 {
		t.Fatalf("rename: %d %v", n, err)
	}
	if got, _ := name(tenant, mine); got != "github.com/acme/new" {
		t.Fatalf("own pipeline name = %q", got)
	}
	if got, _ := name(other, theirs); got != "github.com/acme/old" {
		t.Fatalf("another tenant's pipeline was renamed: %q", got)
	}
	if n, err := lc.SetPipelinesRepositoryArchived(ctx, tenant, "github", cirun.GitHubIssuer, "77", true); err != nil || n != 1 {
		t.Fatalf("archive: %d %v", n, err)
	}
	if _, arch := name(tenant, mine); !arch {
		t.Fatal("pipeline not flagged archived")
	}
	if _, arch := name(other, theirs); arch {
		t.Fatal("another tenant's pipeline was archived")
	}
	if n, _ := lc.SetPipelinesRepositoryArchived(ctx, tenant, "github", cirun.GitHubIssuer, "77", true); n != 0 {
		t.Fatalf("archiving twice changed %d rows", n)
	}
	if n, err := lc.SetPipelinesRepositoryArchived(ctx, tenant, "github", cirun.GitHubIssuer, "77", false); err != nil || n != 1 {
		t.Fatalf("unarchive: %d %v", n, err)
	}
	if _, arch := name(tenant, mine); arch {
		t.Fatal("pipeline still archived")
	}
}
