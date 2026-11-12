package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The decoration queue: only evaluated GitHub runs are queued; a claim takes
// each run once (until it goes stale); retries stop after the cap; writes
// are tenant-scoped. Requires DATABASE_URL.
func TestCIDecorationQueue(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewCIRunRepository(&DB{DB: db})
	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	asset := seedTestAsset(ctx, t, db, tenant)
	now := time.Now().UTC()
	mk := func(provider cirun.Provider, status string) *cirun.Run {
		_, hash, _ := cirun.NewToken()
		exp := now.Add(time.Minute)
		r := &cirun.Run{ID: shared.NewID(), TenantID: tenant, RepositoryAssetID: asset, Provider: provider,
			Issuer: "https://issuer", Repository: "github.com/acme/api", Status: cirun.StatusRunning, TokenHash: hash,
			TokenExpiresAt: &exp, CreatedAt: now, UpdatedAt: now}
		if err := repo.CreateRun(ctx, r); err != nil {
			t.Fatal(err)
		}
		if status == cirun.StatusEvaluated {
			if err := repo.SaveVerdict(ctx, tenant, r.ID, cirun.VerdictPass, []byte(`{}`), now, 0, nil); err != nil {
				t.Fatal(err)
			}
		}
		return r
	}
	gh := mk(cirun.ProviderGitHub, cirun.StatusEvaluated)
	gl := mk(cirun.ProviderAzureDevOps, cirun.StatusEvaluated)
	running := mk(cirun.ProviderGitHub, cirun.StatusRunning)
	// Storing the verdict queues it (one statement: no later step can lose
	// it); another tenant cannot store one on this tenant's run.
	if err := repo.SaveVerdict(ctx, other, running.ID, cirun.VerdictPass, []byte(`{}`), now, 0, nil); err == nil {
		t.Fatal("another tenant stored a verdict")
	}
	state := func(id shared.ID) (string, int) {
		var s string
		var n int
		if err := db.QueryRowContext(ctx, `SELECT decoration_state, decoration_attempts FROM ci_runs WHERE id = $1`, id.String()).Scan(&s, &n); err != nil {
			t.Fatal(err)
		}
		return s, n
	}
	if s, _ := state(gl.ID); s != "" {
		t.Fatalf("azure run queued: %q", s)
	}
	if s, _ := state(running.ID); s != "" {
		t.Fatalf("running run queued: %q", s)
	}
	if s, n := state(gh.ID); s != cirun.DecorationPending || n != 0 {
		t.Fatalf("github run not queued by its verdict: %q %d", s, n)
	}
	claimed, err := repo.ClaimDecorations(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, r := range claimed {
		if r.ID == gh.ID {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("claimed the github run %d times", found)
	}
	again, _ := repo.ClaimDecorations(ctx, 50)
	for _, r := range again {
		if r.ID == gh.ID {
			t.Fatal("a claimed run was claimed again")
		}
	}
	claims := func() int {
		got, err := repo.ClaimDecorations(ctx, 50)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, r := range got {
			if r.ID == gh.ID {
				n++
			}
		}
		return n
	}
	// Retry until the cap, then failed. A retried run waits its backoff
	// (30 s doubling): not claimed at once, claimed once the wait passed.
	for i := 1; i < cirun.MaxDecorationAttempts; i++ {
		if err := repo.FinishDecoration(ctx, tenant, gh.ID, cirun.DecorationRetry, "502"); err != nil {
			t.Fatal(err)
		}
		if s, _ := state(gh.ID); s != cirun.DecorationPending {
			t.Fatalf("retry %d: %q", i, s)
		}
		if n := claims(); n != 0 {
			t.Fatalf("retry %d claimed before its backoff", i)
		}
		wait := 30 * time.Second << (i - 1)
		if wait > 30*time.Minute {
			wait = 30 * time.Minute
		}
		// Just short of the wait: still waiting.
		if _, err := db.ExecContext(ctx, `UPDATE ci_runs SET decoration_updated_at = NOW() - $2::interval WHERE id = $1`,
			gh.ID.String(), (wait - 5*time.Second).String()); err != nil {
			t.Fatal(err)
		}
		if n := claims(); n != 0 {
			t.Fatalf("retry %d claimed %s early", i, 5*time.Second)
		}
		if _, err := db.ExecContext(ctx, `UPDATE ci_runs SET decoration_updated_at = NOW() - $2::interval WHERE id = $1`,
			gh.ID.String(), (wait + time.Second).String()); err != nil {
			t.Fatal(err)
		}
		if n := claims(); n != 1 {
			t.Fatalf("retry %d not claimed after its backoff", i)
		}
	}
	if err := repo.FinishDecoration(ctx, tenant, gh.ID, cirun.DecorationRetry, "502"); err != nil {
		t.Fatal(err)
	}
	if s, n := state(gh.ID); s != cirun.DecorationFailed || n != cirun.MaxDecorationAttempts {
		t.Fatalf("after the cap: %q %d", s, n)
	}
	// Another tenant cannot change it.
	if err := repo.FinishDecoration(ctx, other, gh.ID, cirun.DecorationPosted, ""); err != nil {
		t.Fatal(err)
	}
	if s, _ := state(gh.ID); s != cirun.DecorationFailed {
		t.Fatalf("cross-tenant finish changed the run: %q", s)
	}
}

// PullRequestPassed reads the last evaluated non-fork run of the pull
// request, tenant-scoped.
func TestCIPullRequestPassed(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewCIRunRepository(&DB{DB: db})
	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	asset := seedTestAsset(ctx, t, db, tenant)
	at := time.Now().UTC().Add(-time.Hour)
	judge := func(pr, verdict string, fork bool, when time.Time) {
		_, hash, _ := cirun.NewToken()
		r := &cirun.Run{ID: shared.NewID(), TenantID: tenant, RepositoryAssetID: asset, Provider: cirun.ProviderGitHub,
			Issuer: "https://i", Repository: "github.com/acme/api", PullRequest: pr, Fork: fork, Status: cirun.StatusRunning,
			TokenHash: hash, CreatedAt: when, UpdatedAt: when}
		if err := repo.CreateRun(ctx, r); err != nil {
			t.Fatal(err)
		}
		if err := repo.SaveVerdict(ctx, tenant, r.ID, verdict, []byte(`{}`), when, 0, nil); err != nil {
			t.Fatal(err)
		}
	}
	judge("5", cirun.VerdictPass, false, at)
	judge("5", cirun.VerdictFail, false, at.Add(time.Minute)) // last verdict fails
	judge("6", cirun.VerdictFail, false, at)
	judge("6", cirun.VerdictPass, false, at.Add(time.Minute))
	judge("7", cirun.VerdictPass, true, at) // only a fork run passed
	for pr, want := range map[string]bool{"5": false, "6": true, "7": false, "8": false} {
		if got, err := repo.PullRequestPassed(ctx, tenant, asset, pr); err != nil || got != want {
			t.Fatalf("pr %s: %v %v, want %v", pr, got, err, want)
		}
	}
	if got, _ := repo.PullRequestPassed(ctx, other, asset, "6"); got {
		t.Fatal("another tenant read the verdict")
	}
}

// CommitVerdicts returns the latest verdict of each pipeline on the commits
// of the repository: a later run of the same pipeline replaces its earlier
// one, another pipeline's run does not; runs still running, other commits,
// other repositories and other tenants are not read.
func TestCICommitVerdicts(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewCIRunRepository(&DB{DB: db})
	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	asset, asset2 := seedTestAsset(ctx, t, db, tenant), seedTestAsset(ctx, t, db, tenant)
	otherAsset := seedTestAsset(ctx, t, db, other)
	now := time.Now().UTC()
	pipeline := func(tid, aid shared.ID, path string) *shared.ID {
		p, _, err := repo.UpsertPipeline(ctx, &cirun.Pipeline{ID: shared.NewID(), TenantID: tid, Provider: cirun.ProviderGitHub,
			Issuer: cirun.GitHubIssuer, ExternalRepoID: "4242", WorkflowPath: path, RepositoryAssetID: aid,
			RepositoryName: "github.com/acme/api", CreatedAt: now}, false, cirun.PipelineCaps{})
		if err != nil {
			t.Fatal(err)
		}
		return &p.ID
	}
	scan, extra := pipeline(tenant, asset, ".github/workflows/scan.yml"), pipeline(tenant, asset, ".github/workflows/extra.yml")
	judge := func(tid, aid shared.ID, pid *shared.ID, sha, verdict string, when time.Time) shared.ID {
		_, hash, _ := cirun.NewToken()
		r := &cirun.Run{ID: shared.NewID(), TenantID: tid, RepositoryAssetID: aid, PipelineID: pid, Provider: cirun.ProviderGitHub,
			Issuer: "https://i", Repository: "github.com/acme/api", CommitSHA: sha, Status: cirun.StatusRunning,
			TokenHash: hash, CreatedAt: when, UpdatedAt: when}
		if err := repo.CreateRun(ctx, r); err != nil {
			t.Fatal(err)
		}
		if verdict != "" {
			if err := repo.SaveVerdict(ctx, tid, r.ID, verdict, []byte(`{"would_fail":true}`), when, 0, nil); err != nil {
				t.Fatal(err)
			}
		}
		return r.ID
	}
	at := now.Add(-time.Hour)
	judge(tenant, asset, scan, "aaa", cirun.VerdictFail, at)
	rerun := judge(tenant, asset, scan, "aaa", cirun.VerdictPass, at.Add(time.Minute)) // same pipeline: replaces
	failed := judge(tenant, asset, extra, "bbb", cirun.VerdictFail, at)                // the check's head commit
	alone := judge(tenant, asset, nil, "AAA", cirun.VerdictPass, at)                   // no pipeline: counts alone
	judge(tenant, asset, extra, "aaa", "", at.Add(2*time.Minute))                      // still running
	judge(tenant, asset, scan, "ccc", cirun.VerdictFail, at)                           // another commit
	judge(tenant, asset2, nil, "aaa", cirun.VerdictFail, at)                           // another repository
	judge(other, otherAsset, nil, "aaa", cirun.VerdictFail, at)                        // another tenant

	got, err := repo.CommitVerdicts(ctx, tenant, asset, []string{"aaa", "BBB"})
	if err != nil {
		t.Fatal(err)
	}
	byRun := map[shared.ID]cirun.CommitVerdict{}
	for _, v := range got {
		byRun[v.RunID] = v
	}
	if len(got) != 3 || byRun[rerun].Verdict != cirun.VerdictPass || byRun[failed].Verdict != cirun.VerdictFail ||
		byRun[alone].Verdict != cirun.VerdictPass || !byRun[failed].WouldFail {
		t.Fatalf("verdicts = %+v", got)
	}
	// Another tenant reading this tenant's asset sees nothing.
	if got, err := repo.CommitVerdicts(ctx, other, asset, []string{"aaa", "bbb"}); err != nil || len(got) != 0 {
		t.Fatalf("cross-tenant = %+v %v", got, err)
	}
	if got, err := repo.CommitVerdicts(ctx, tenant, asset, []string{" "}); err != nil || got != nil {
		t.Fatalf("no commit = %+v %v", got, err)
	}
}
