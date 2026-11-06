package controller

import (
	"context"
	"database/sql"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// rendezvousStats makes every replica that reaches the render step wait (up to
// a deadline) until `want` replicas have reached it, so two schedulers that both
// picked the same due schedule are guaranteed to overlap in time.
type rendezvousStats struct {
	fakeStats
	want    int32
	arrived atomic.Int32
	all     chan struct{}
	once    sync.Once
}

func (r *rendezvousStats) GetStats(ctx context.Context, tid shared.ID, uid *shared.ID, f vulnerability.FindingStatsFilter) (*vulnerability.FindingStats, error) {
	if r.arrived.Add(1) >= r.want {
		r.once.Do(func() { close(r.all) })
	}
	select {
	case <-r.all:
	case <-time.After(2 * time.Second):
	}
	return r.fakeStats.GetStats(ctx, tid, uid, f)
}

type countingEmailer struct{ sent atomic.Int32 }

func (c *countingEmailer) IsConfigured() bool { return true }
func (c *countingEmailer) SendReport(context.Context, string, []string, string, string) error {
	c.sent.Add(1)
	return nil
}

// TestReportScheduler_TwoReplicasDeliverOnce: with two API replicas, both report
// schedulers tick, both list the same due schedule, and before the per-row claim
// both rendered and emailed it. Exactly one replica may deliver a due slot.
//
// DB-gated: needs DATABASE_URL pointing at app_test (never the live DB).
func TestReportScheduler_TwoReplicasDeliverOnce(t *testing.T) {
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
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1,$2,$3)`,
		tenantID.String(), "report-claim-test", "rptclaim-"+tenantID.String()); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID.String()) })

	scheduleID := shared.NewID()
	due := time.Now().Add(-time.Minute).UTC().Truncate(time.Microsecond)
	if _, err := db.ExecContext(ctx, `
		INSERT INTO report_schedules (id, tenant_id, name, report_type, format, recipients,
			delivery_channel, cron_expression, timezone, is_active, next_run_at, created_at, updated_at)
		VALUES ($1, $2, 'weekly digest', 'executive_summary', 'html',
			'[{"email":"secops@example.invalid","name":"SecOps"}]', 'email', '0 8 * * 1', 'UTC', true, $3, now(), now())`,
		scheduleID.String(), tenantID.String(), due); err != nil {
		t.Fatalf("insert schedule: %v", err)
	}

	repo := postgres.NewReportScheduleRepository(&postgres.DB{DB: db})
	stats := &rendezvousStats{want: 2, all: make(chan struct{})}
	mail := &countingEmailer{}
	newReplica := func() *ReportScheduler {
		return NewReportScheduler(repo, stats, mail, nil, nil, ReportSchedulerConfig{Interval: time.Minute}, logger.NewNop())
	}
	a, b := newReplica(), newReplica()

	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, r := range []*ReportScheduler{a, b} {
		wg.Add(1)
		go func(r *ReportScheduler) {
			defer wg.Done()
			<-start
			if _, err := r.Reconcile(ctx); err != nil {
				t.Errorf("reconcile: %v", err)
			}
		}(r)
	}
	close(start)
	wg.Wait()

	if got := mail.sent.Load(); got != 1 {
		t.Fatalf("two replicas delivered the same due schedule %d times, want exactly 1", got)
	}

	var runCount int
	var next time.Time
	if err := db.QueryRowContext(ctx, `SELECT run_count, next_run_at FROM report_schedules WHERE id=$1`,
		scheduleID.String()).Scan(&runCount, &next); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if runCount != 1 {
		t.Fatalf("run_count = %d, want 1", runCount)
	}
	if !next.After(time.Now()) {
		t.Fatalf("next_run_at = %v, want a future slot", next)
	}
}
