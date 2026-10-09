package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/lib/pq"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/scancoverage"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// rendezvousCoverageSource lists real candidates, then holds each replica until
// both have listed, so two replicas are guaranteed to plan from the same view.
type rendezvousCoverageSource struct {
	repo    *ScanCoverageRepository
	cfg     scancoverage.CoverageConfig
	arrived atomic.Int32
	all     chan struct{}
	once    sync.Once
}

func (s *rendezvousCoverageSource) ListActiveCoverage(context.Context) ([]scancoverage.CoverageConfig, error) {
	return []scancoverage.CoverageConfig{s.cfg}, nil
}

func (s *rendezvousCoverageSource) ListCandidates(ctx context.Context, tid shared.ID, limit int) ([]scancoverage.Candidate, error) {
	c, err := s.repo.ListCandidates(ctx, tid, limit)
	if s.arrived.Add(1) >= 2 {
		s.once.Do(func() { close(s.all) })
	}
	select {
	case <-s.all:
	case <-time.After(2 * time.Second):
	}
	return c, err
}

func (s *rendezvousCoverageSource) ActiveIPs(context.Context, shared.ID) (int, error) { return 0, nil }

type countingDispatcher struct {
	mu      sync.Mutex
	targets map[string]int
}

func (d *countingDispatcher) DispatchTenableScan(_ context.Context, in scancoverage.DispatchTenableInput) (shared.ID, string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, t := range in.Targets {
		d.targets[t]++
	}
	return shared.NewID(), "session-" + shared.NewID().String()[28:], nil
}

// TestCoverageScheduler_TwoReplicasNeverDispatchAnAssetTwice: every API replica
// runs the coverage scheduler. Before the per-row claim, both listed the same
// least-recently-scanned assets and both dispatched them, so every asset in the
// batch was scanned twice per cycle (and, on a capped engine, counted twice
// against the license).
//
// DB-gated: needs DATABASE_URL pointing at app_test (never the live DB).
func TestCoverageScheduler_TwoReplicasNeverDispatchAnAssetTwice(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	ctx := context.Background()

	tenantID := shared.NewID()
	mustExec(t, db, `INSERT INTO tenants (id, name, slug) VALUES ($1,$2,$3)`,
		tenantID.String(), "coverage-claim-test", "covclaim-"+tenantID.String())
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID.String()) })

	// Six hosts: three never dispatched, three dispatched long ago (exercises
	// both the insert and the update path of the claim).
	for i := 1; i <= 6; i++ {
		var id string
		if err := db.QueryRowContext(ctx,
			`INSERT INTO assets (tenant_id, name, asset_type, status) VALUES ($1,$2,'host','active') RETURNING id`,
			tenantID.String(), fmt.Sprintf("10.9.0.%d", i)).Scan(&id); err != nil {
			t.Fatalf("insert asset: %v", err)
		}
		if i > 3 {
			mustExec(t, db, `INSERT INTO scan_coverage_state (asset_id, tenant_id, last_dispatched_at)
				VALUES ($1, $2, now() - interval '30 days')`, id, tenantID.String())
		}
	}

	repo := NewScanCoverageRepository(&DB{DB: db})
	src := &rendezvousCoverageSource{
		repo: repo,
		cfg: scancoverage.CoverageConfig{
			TenantID:     tenantID,
			Engine:       "nessus_pro",
			Policy:       scancoverage.LicensePolicy{Mode: scancoverage.LicenseUnlimited},
			DefaultBatch: 6,
		},
		all: make(chan struct{}),
	}
	disp := &countingDispatcher{targets: map[string]int{}}
	newReplica := func() *scancoverage.Scheduler {
		return scancoverage.NewScheduler(src, disp, repo, &scancoverage.SchedulerConfig{Gate: allowAllCoverageGate{}})
	}

	var wg sync.WaitGroup
	for _, s := range []*scancoverage.Scheduler{newReplica(), newReplica()} {
		wg.Add(1)
		go func(s *scancoverage.Scheduler) {
			defer wg.Done()
			if _, err := s.RunOnce(ctx); err != nil {
				t.Errorf("run once: %v", err)
			}
		}(s)
	}
	wg.Wait()

	if len(disp.targets) != 6 {
		t.Fatalf("dispatched %d distinct assets, want all 6: %v", len(disp.targets), disp.targets)
	}
	for target, n := range disp.targets {
		if n != 1 {
			t.Errorf("asset %s dispatched %d times in one cycle by two replicas, want 1", target, n)
		}
	}

	var withCommand int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM scan_coverage_state WHERE tenant_id=$1 AND last_command_id IS NOT NULL`,
		tenantID.String()).Scan(&withCommand); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if withCommand != 6 {
		t.Fatalf("%d assets record the command that scans them, want 6", withCommand)
	}
}

// TestScanCoverageRepository_ClaimAndRelease: a claim moves only cursors that
// still hold the planned value; a release puts them back (and removes the rows
// the claim created), so a failed dispatch does not push assets to the back of
// the rotation.
func TestScanCoverageRepository_ClaimAndRelease(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	ctx := context.Background()

	tenantID := shared.NewID()
	mustExec(t, db, `INSERT INTO tenants (id, name, slug) VALUES ($1,$2,$3)`,
		tenantID.String(), "coverage-release-test", "covrel-"+tenantID.String())
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID.String()) })

	insertHost := func(name string) string {
		var id string
		if err := db.QueryRowContext(ctx,
			`INSERT INTO assets (tenant_id, name, asset_type, status) VALUES ($1,$2,'host','active') RETURNING id`,
			tenantID.String(), name).Scan(&id); err != nil {
			t.Fatalf("insert asset: %v", err)
		}
		return id
	}
	fresh := insertHost("10.8.0.1")
	old := insertHost("10.8.0.2")
	moved := insertHost("10.8.0.3")
	oldAt := time.Now().Add(-30 * 24 * time.Hour).UTC().Truncate(time.Microsecond)
	for _, id := range []string{old, moved} {
		mustExec(t, db, `INSERT INTO scan_coverage_state (asset_id, tenant_id, last_dispatched_at) VALUES ($1,$2,$3)`,
			id, tenantID.String(), oldAt)
	}
	// `moved` was dispatched by someone else after this caller planned.
	mustExec(t, db, `UPDATE scan_coverage_state SET last_dispatched_at = now() WHERE asset_id=$1`, moved)

	repo := NewScanCoverageRepository(&DB{DB: db})
	batch := []scancoverage.Candidate{
		{AssetID: fresh, Target: "10.8.0.1"},
		{AssetID: old, Target: "10.8.0.2", LastScannedAt: &oldAt},
		{AssetID: moved, Target: "10.8.0.3", LastScannedAt: &oldAt},
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	claimed, err := repo.ClaimBatch(ctx, tenantID, batch, at)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	got := map[string]bool{}
	for _, id := range claimed {
		got[id] = true
	}
	if len(claimed) != 2 || !got[fresh] || !got[old] || got[moved] {
		t.Fatalf("claimed %v, want fresh+old and not the asset moved since planning", claimed)
	}
	if again, err := repo.ClaimBatch(ctx, tenantID, batch, at.Add(time.Second)); err != nil || len(again) != 0 {
		t.Fatalf("second claim of the same plan won %v (err %v), want nothing", again, err)
	}

	if err := repo.ReleaseBatch(ctx, tenantID, batch[:2], at); err != nil {
		t.Fatalf("release: %v", err)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM scan_coverage_state WHERE asset_id=$1`, fresh).Scan(&n); err != nil || n != 0 {
		t.Fatalf("fresh asset cursor rows after release = %d (err %v), want 0", n, err)
	}
	var back time.Time
	if err := db.QueryRowContext(ctx, `SELECT last_dispatched_at FROM scan_coverage_state WHERE asset_id=$1`, old).Scan(&back); err != nil {
		t.Fatalf("read old cursor: %v", err)
	}
	if !back.Equal(oldAt) {
		t.Fatalf("old cursor after release = %v, want restored %v", back, oldAt)
	}
}

// allowAllCoverageGate lets every target through, unzoned.
type allowAllCoverageGate struct{}

func (allowAllCoverageGate) ResolveDispatchTargets(_ context.Context, in scanapp.DispatchTargetsInput) (*scanapp.DispatchTargets, error) {
	return &scanapp.DispatchTargets{Allowed: in.Targets}, nil
}
