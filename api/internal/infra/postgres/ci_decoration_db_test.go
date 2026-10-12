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
			if err := repo.SaveVerdict(ctx, tenant, r.ID, cirun.VerdictPass, []byte(`{}`), now); err != nil {
				t.Fatal(err)
			}
		}
		return r
	}
	gh := mk(cirun.ProviderGitHub, cirun.StatusEvaluated)
	gl := mk(cirun.ProviderGitLab, cirun.StatusEvaluated)
	running := mk(cirun.ProviderGitHub, cirun.StatusRunning)
	for _, r := range []*cirun.Run{gh, gl, running} {
		if err := repo.MarkDecorationPending(ctx, tenant, r.ID); err != nil {
			t.Fatal(err)
		}
	}
	// Another tenant cannot queue this tenant's run.
	if err := repo.MarkDecorationPending(ctx, other, gh.ID); err != nil {
		t.Fatal(err)
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
		t.Fatalf("gitlab run queued: %q", s)
	}
	if s, _ := state(running.ID); s != "" {
		t.Fatalf("running run queued: %q", s)
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
	// Retry until the cap, then failed.
	for i := 1; i < cirun.MaxDecorationAttempts; i++ {
		if err := repo.FinishDecoration(ctx, tenant, gh.ID, cirun.DecorationRetry, "502"); err != nil {
			t.Fatal(err)
		}
		if s, _ := state(gh.ID); s != cirun.DecorationPending {
			t.Fatalf("retry %d: %q", i, s)
		}
		if _, err := repo.ClaimDecorations(ctx, 50); err != nil {
			t.Fatal(err)
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
