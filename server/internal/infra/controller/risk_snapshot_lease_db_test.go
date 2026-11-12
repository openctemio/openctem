package controller

import (
	"context"
	"database/sql"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// countedRiskSnapshot counts the reconciles that really ran and holds each
// one long enough for the other replica's tick to overlap it. Embedding
// keeps the controller's own Exclusive (or its absence).
type countedRiskSnapshot struct {
	*RiskSnapshotController
	runs atomic.Int32
}

func (c *countedRiskSnapshot) Reconcile(ctx context.Context) (int, error) {
	c.runs.Add(1)
	n, err := c.RiskSnapshotController.Reconcile(ctx)
	time.Sleep(300 * time.Millisecond)
	return n, err
}

// The risk snapshot is a full GROUP BY over assets and findings of every
// tenant. With several API replicas each ran it on every tick; it takes the
// controller lease now, so two replicas ticking together run it once.
func TestRiskSnapshot_TwoReplicasRunItOnce_DB(t *testing.T) {
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping two-replica risk snapshot test")
	}
	open := func() *sql.DB {
		db, err := sql.Open("postgres", url)
		if err != nil {
			t.Fatalf("open db: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if err := db.PingContext(context.Background()); err != nil {
			t.Skipf("cannot reach DATABASE_URL: %v", err)
		}
		return db
	}
	dbA, dbB := open(), open()
	_, _ = dbA.Exec(`DELETE FROM controller_leases WHERE name = 'controller:risk-snapshot'`)

	ctrl := &countedRiskSnapshot{RiskSnapshotController: NewRiskSnapshotController(dbA, logger.NewNop())}
	replica := func(db *sql.DB, holder string) *Manager {
		return NewManager(&ManagerConfig{Logger: logger.NewNop(),
			Leases: postgres.NewControllerLeaseRepository(&postgres.DB{DB: db}), LeaseHolder: holder})
	}
	a, b := replica(dbA, "replica-a"), replica(dbB, "replica-b")

	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, m := range []*Manager{a, b} {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; m.reconcileOnce(context.Background(), ctrl) }()
	}
	close(start)
	wg.Wait()

	if got := ctrl.runs.Load(); got != 1 {
		t.Fatalf("risk snapshot ran %d times for one tick on two replicas, want 1", got)
	}

	// Without the lease (a replica with no lease store) two runs at once
	// still leave one row per tenant and day: (tenant_id, snapshot_date) is
	// unique and the insert upserts on it.
	tenant := shared.NewID()
	if _, err := dbA.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'risk snapshot replicas', $2)`, tenant.String(), "rsr-"+tenant.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = dbA.Exec(`DELETE FROM tenants WHERE id = $1`, tenant.String()) })
	runA, runB := NewRiskSnapshotController(dbA, logger.NewNop()), NewRiskSnapshotController(dbB, logger.NewNop())
	var errA, errB error
	wg.Add(2)
	go func() { defer wg.Done(); _, errA = runA.Reconcile(context.Background()) }()
	go func() { defer wg.Done(); _, errB = runB.Reconcile(context.Background()) }()
	wg.Wait()
	if errA != nil || errB != nil {
		t.Fatalf("concurrent runs: %v / %v", errA, errB)
	}
	var rows int
	if err := dbA.QueryRow(`SELECT count(*) FROM risk_snapshots WHERE tenant_id = $1`, tenant.String()).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("snapshot rows for one tenant and day = %d, want 1", rows)
	}
}
