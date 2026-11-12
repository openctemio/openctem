package widgets

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	dashboardapp "github.com/openctemio/openctem/api/internal/app/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// storedSnapshots serves one stored snapshot and records writes.
type storedSnapshots struct {
	dashboard.SnapshotStore
	snap *dashboard.Snapshot
	puts int
}

func (f *storedSnapshots) GetSnapshot(context.Context, shared.ID, shared.ID) (*dashboard.Snapshot, error) {
	return f.snap, nil
}

func (f *storedSnapshots) PutSnapshot(_ context.Context, s dashboard.Snapshot) error {
	f.puts++
	f.snap = &s
	return nil
}

func (f *storedSnapshots) TouchSnapshot(context.Context, shared.ID, shared.ID, time.Time) error {
	return nil
}

// builtFacts answers FactsBuiltAt with builtAt and counts the reads.
type builtFacts struct {
	dashboard.FactReader
	builtAt *time.Time
	reads   int
}

func (f *builtFacts) FactsBuiltAt(context.Context, shared.ID) (*time.Time, error) {
	f.reads++
	return f.builtAt, nil
}

// A snapshot computed before the organization's facts were first built holds
// only "being built" widgets. Once the facts exist, opening the dashboard
// computes it again instead of serving that snapshot until its next
// scheduled refresh (an hour later by default).
func TestRead_SnapshotFromBeforeFactsBuilt(t *testing.T) {
	tenant, user := shared.NewID(), shared.NewID()
	d, err := dashboard.NewOrgDashboard(tenant, "CTEM", "", 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := dashboardapp.Caller{TenantID: tenant, UserID: user}
	now := time.Date(2026, 11, 11, 17, 43, 0, 0, time.UTC)
	stored := func(builtAt *time.Time) *dashboard.Snapshot {
		raw, err := json.Marshal(DashboardData{DashboardID: d.ID().String(), Scope: "organization", FactsBuiltAt: builtAt, ComputedAt: now.Add(-4 * time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
		return &dashboard.Snapshot{
			TenantID: tenant, DashboardID: d.ID(), Kind: d.Kind(), OwnerID: d.UserID(),
			ScopeKey: orgScopeKey, LayoutHash: layoutHash(d.Widgets()), Data: raw, ComputedAt: now.Add(-4 * time.Minute),
		}
	}
	svc := func(snaps *storedSnapshots, facts *builtFacts) *Service {
		s := &Service{facts: facts, limiter: newLimiter(1, 1, 1), logger: logger.NewNop(), now: func() time.Time { return now }}
		s.snapshots = snaps
		return s
	}
	built := now.Add(-time.Minute)

	// Facts built since the snapshot: computed again and stored.
	snaps, facts := &storedSnapshots{snap: stored(nil)}, &builtFacts{builtAt: &built}
	out, err := svc(snaps, facts).read(context.Background(), c, d, orgScope(tenant), false)
	if err != nil {
		t.Fatal(err)
	}
	if out.FactsBuiltAt == nil || !out.FactsBuiltAt.Equal(built) {
		t.Errorf("facts_built_at = %v, want %v (the stale snapshot was served)", out.FactsBuiltAt, built)
	}
	if snaps.puts != 1 {
		t.Errorf("snapshot stored %d times, want 1", snaps.puts)
	}

	// Facts still being built: the stored snapshot is served, nothing written.
	snaps, facts = &storedSnapshots{snap: stored(nil)}, &builtFacts{}
	out, err = svc(snaps, facts).read(context.Background(), c, d, orgScope(tenant), false)
	if err != nil {
		t.Fatal(err)
	}
	if out.FactsBuiltAt != nil || snaps.puts != 0 {
		t.Errorf("facts not built: facts_built_at = %v, puts = %d, want nil and 0", out.FactsBuiltAt, snaps.puts)
	}

	// A snapshot of built facts is served without asking for the status.
	snaps, facts = &storedSnapshots{snap: stored(&built)}, &builtFacts{builtAt: &built}
	if _, err := svc(snaps, facts).read(context.Background(), c, d, orgScope(tenant), false); err != nil {
		t.Fatal(err)
	}
	if snaps.puts != 0 || facts.reads != 0 {
		t.Errorf("built snapshot: puts = %d, status reads = %d, want 0 and 0", snaps.puts, facts.reads)
	}
}
