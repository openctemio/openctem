package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/exploration"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// The precomputed figures count the tenant's own leads only; scoped figures
// count only leads on assets in the reader's data scope.
func TestExplorationRollups_DB(t *testing.T) {
	f := newCoverageFixture(t)
	other := newCoverageFixture(t)
	repo := NewExplorationRepository(&DB{DB: f.db})
	ctx := context.Background()

	ex, _ := repo.EnsureContinuous(ctx, f.tenant)
	if _, err := repo.Rollup(ctx, f.tenant, ex); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("before the first refresh: %v", err)
	}
	leadOn(t, repo, f, f.host)
	done, _ := leadOn(t, repo, f, f.otherHost)
	leadOn(t, repo, other, other.host)
	leadOn(t, repo, other, other.otherHost)

	l, _ := repo.GetLead(ctx, f.tenant, done.ID, nil)
	for _, s := range []exploration.LeadState{exploration.StateRunning, exploration.StateDone} {
		if err := l.Move(s, l.UpdatedAt); err != nil {
			t.Fatal(err)
		}
		if err := repo.SaveLead(ctx, l); err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.AddVerdict(ctx, exploration.Verdict{TenantID: f.tenant, LeadID: l.ID, Verdict: exploration.VerdictProven,
		Tier: exploration.TierDeterministic, Checker: "scan_run"}); err != nil {
		t.Fatal(err)
	}

	if err := repo.RefreshRollup(ctx, f.tenant, ex); err != nil {
		t.Fatal(err)
	}
	s, err := repo.Rollup(ctx, f.tenant, ex)
	if err != nil {
		t.Fatal(err)
	}
	if s.Open != 1 || s.Done30d != 1 || s.Proven30d != 1 || s.RuleShare == nil || *s.RuleShare != 1 || s.MedianVerdictSeconds == nil {
		t.Fatalf("rollup = %+v", s)
	}
	// Another tenant's id for this exploration finds nothing.
	if _, err := repo.Rollup(ctx, other.tenant, ex); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant rollup read: %v", err)
	}

	member := f.user(t)
	f.exec(t, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3)`, member, f.tenant, f.host)
	scoped, err := repo.ScopedSummary(ctx, f.tenant, ex, &shared.DataScope{TenantID: f.tenant, UserID: member})
	if err != nil {
		t.Fatal(err)
	}
	if !scoped.Scoped || scoped.Open != 1 || scoped.Done30d != 0 {
		t.Fatalf("scoped = %+v, want only the in-scope open lead", scoped)
	}
	none, _ := repo.ScopedSummary(ctx, f.tenant, ex, &shared.DataScope{TenantID: f.tenant, UserID: f.user(t)})
	if none.Open != 0 || none.Done30d != 0 {
		t.Fatalf("no scope rows: %+v", none)
	}
}
