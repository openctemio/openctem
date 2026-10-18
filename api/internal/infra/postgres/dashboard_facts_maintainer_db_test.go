package postgres

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/dashboardfact"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The facts maintainer (migration dashboard_facts_maintainer): the queue
// claim recomputes and deletes atomically, two maintainers never lose or
// double-apply a change, full runs count drift, the rebuild request is rate
// limited, and nothing crosses tenants.

func drainFacts(ctx context.Context, t *testing.T, repo *DashboardFactsRepository, tenant shared.ID) dashboardfact.DirtyBatch {
	t.Helper()
	var total dashboardfact.DirtyBatch
	for i := 0; i < 1000; i++ {
		b, err := repo.ProcessDirty(ctx, tenant, 50)
		if err != nil {
			t.Fatalf("process dirty: %v", err)
		}
		if b.Claimed == 0 {
			return total
		}
		total.Claimed += b.Claimed
		total.Recomputed += b.Recomputed
		total.Changed += b.Changed
	}
	t.Fatal("queue never drained")
	return total
}

func runToEnd(ctx context.Context, t *testing.T, repo *DashboardFactsRepository, tenant shared.ID, kind dashboardfact.RunKind) int {
	t.Helper()
	if _, err := repo.StartRun(ctx, tenant, kind); err != nil {
		t.Fatalf("start run: %v", err)
	}
	drift := 0
	for i := 0; i < 1000; i++ {
		s, err := repo.RunStep(ctx, tenant, 2)
		if err != nil {
			t.Fatalf("run step: %v", err)
		}
		if s.Kind != kind {
			t.Fatalf("run kind %q, want %q", s.Kind, kind)
		}
		drift += s.Drift
		if s.Done {
			return drift
		}
	}
	t.Fatal("run never finished")
	return 0
}

func factCount(ctx context.Context, t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func TestDashboardFactsMaintainer_ProcessDirty_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewDashboardFactsRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	assets := []shared.ID{seedOwnedAsset(ctx, t, db, tenant, nil), seedOwnedAsset(ctx, t, db, tenant, nil)}
	otherAsset := seedOwnedAsset(ctx, t, db, other, nil)
	seedFactMatrix(ctx, t, db, tenant, assets, seedFactCampaign(ctx, t, db, tenant))
	seedFactMatrix(ctx, t, db, other, []shared.ID{otherAsset}, seedFactCampaign(ctx, t, db, other))
	otherQueue := factCount(ctx, t, db, `SELECT count(*) FROM dash_dirty_assets WHERE tenant_id = $1`, other.String())

	t.Run("claim recomputes the marked assets and deletes the claimed rows", func(t *testing.T) {
		b := drainFacts(ctx, t, repo, tenant)
		if b.Claimed == 0 || b.Recomputed == 0 || b.Changed == 0 {
			t.Fatalf("drain did nothing: %+v", b)
		}
		if d := symmetricDiff(ctx, t, db, factStateSQL, directStateSQL(), tenant.String()); d != 0 {
			t.Fatalf("after draining, F1 differs from findings in %d rows", d)
		}
		if n := factCount(ctx, t, db, `SELECT count(*) FROM dash_dirty_assets WHERE tenant_id = $1`, tenant.String()); n != 0 {
			t.Fatalf("%d queue rows left", n)
		}
	})

	t.Run("other tenants are untouched", func(t *testing.T) {
		if n := factCount(ctx, t, db, `SELECT count(*) FROM dash_dirty_assets WHERE tenant_id = $1`, other.String()); n != otherQueue {
			t.Fatalf("other tenant's queue went from %d to %d rows", otherQueue, n)
		}
		if n := factCount(ctx, t, db, `SELECT count(*) FROM dash_asset_state WHERE tenant_id = $1`, other.String()); n != 0 {
			t.Fatalf("processing one tenant wrote %d fact rows of another", n)
		}
	})

	t.Run("membership and ownership marks are consumed without a recompute", func(t *testing.T) {
		gid := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO asset_groups (id, tenant_id, name) VALUES ($1, $2, 'maint group')`, gid.String(), tenant.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO asset_group_members (asset_group_id, asset_id) VALUES ($1, $2)`, gid.String(), assets[0].String()); err != nil {
			t.Fatal(err)
		}
		b := drainFacts(ctx, t, repo, tenant)
		if b.Claimed != 1 || b.Recomputed != 0 {
			t.Fatalf("group mark: %+v, want 1 claimed, 0 recomputed", b)
		}
	})

	t.Run("a rolled-back claim keeps the rows and the facts", func(t *testing.T) {
		if _, err := db.ExecContext(ctx, `UPDATE findings SET severity = 'critical' WHERE tenant_id = $1 AND asset_id = $2 AND severity = 'low'`,
			tenant.String(), assets[1].String()); err != nil {
			t.Fatal(err)
		}
		before := factCount(ctx, t, db, `SELECT count(*) FROM dash_dirty_assets WHERE tenant_id = $1`, tenant.String())
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		var claimed int
		if err := tx.QueryRowContext(ctx, `SELECT claimed FROM dash_process_dirty($1, 100)`, tenant.String()).Scan(&claimed); err != nil || claimed == 0 {
			t.Fatalf("claim in tx: %d (%v)", claimed, err)
		}
		_ = tx.Rollback()
		if n := factCount(ctx, t, db, `SELECT count(*) FROM dash_dirty_assets WHERE tenant_id = $1`, tenant.String()); n != before {
			t.Fatalf("queue after rollback: %d rows, want %d", n, before)
		}
		if d := symmetricDiff(ctx, t, db, factStateSQL, directStateSQL(), tenant.String()); d == 0 {
			t.Fatal("a rolled-back recompute left its facts behind")
		}
		drainFacts(ctx, t, repo, tenant)
		if d := symmetricDiff(ctx, t, db, factStateSQL, directStateSQL(), tenant.String()); d != 0 {
			t.Fatalf("F1 differs in %d rows after the retry", d)
		}
	})

	t.Run("a mark held by a running writer is neither claimed nor deleted", func(t *testing.T) {
		w, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = w.Rollback() }()
		if _, err := w.ExecContext(ctx, `UPDATE findings SET status = 'confirmed' WHERE tenant_id = $1 AND asset_id = $2 AND status = 'new'`,
			tenant.String(), assets[0].String()); err != nil {
			t.Fatal(err)
		}
		// The writer's own row is invisible until it commits; the claim
		// neither waits for it nor deletes it.
		done := make(chan error, 1)
		go func() { _, err := repo.ProcessDirty(ctx, tenant, 100); done <- err }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the claim waited for a running writer")
		}
		if err := w.Commit(); err != nil {
			t.Fatal(err)
		}
		if got := dirtyRows(ctx, t, db, tenant); got[dirtyRow{assets[0].String(), 1}] != 1 {
			t.Fatalf("the writer's mark was lost: %v", got)
		}
		drainFacts(ctx, t, repo, tenant)
		if d := symmetricDiff(ctx, t, db, factStateSQL, directStateSQL(), tenant.String()); d != 0 {
			t.Fatalf("F1 differs in %d rows", d)
		}
	})
}

// Two maintainers and concurrent writers on the same tenant: no error (no
// deadlock), no lost change, facts equal the findings at the end.
func TestDashboardFactsMaintainer_TwoMaintainers_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewDashboardFactsRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	assets := make([]shared.ID, 6)
	for i := range assets {
		assets[i] = seedOwnedAsset(ctx, t, db, tenant, nil)
	}
	seedFactMatrix(ctx, t, db, tenant, assets, seedFactCampaign(ctx, t, db, tenant))

	stop := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for m := 0; m < 2; m++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := repo.ProcessDirty(ctx, tenant, 3); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	statuses := []string{"confirmed", "in_progress", "resolved", "new", "accepted"}
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				a := assets[(i+w)%len(assets)]
				if _, err := db.ExecContext(ctx, `UPDATE findings SET status = $3, resolved_at = now()
					WHERE tenant_id = $1 AND asset_id = $2 AND status NOT IN ('draft', 'in_review')`,
					tenant.String(), a.String(), statuses[(i+w)%len(statuses)]); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	time.Sleep(3 * time.Second)
	close(stop)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent maintainer or writer failed: %v", err)
	}
	drainFacts(ctx, t, repo, tenant)
	if d := symmetricDiff(ctx, t, db, factStateSQL, directStateSQL(), tenant.String()); d != 0 {
		t.Fatalf("after two maintainers, F1 differs from findings in %d rows", d)
	}
}

func TestDashboardFactsMaintainer_RunsAndDrift_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewDashboardFactsRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	assets := []shared.ID{seedOwnedAsset(ctx, t, db, tenant, nil), seedOwnedAsset(ctx, t, db, tenant, nil)}
	seedFactMatrix(ctx, t, db, tenant, assets, seedFactCampaign(ctx, t, db, tenant))
	otherAsset := seedOwnedAsset(ctx, t, db, other, nil)
	seedFactMatrix(ctx, t, db, other, []shared.ID{otherAsset}, seedFactCampaign(ctx, t, db, other))
	clearDirty(ctx, t, db, tenant)

	pendingKind := func(t *testing.T, tid shared.ID) dashboardfact.RunKind {
		t.Helper()
		runs, err := repo.PendingRunsForPlatform(ctx, 24*time.Hour, 100000)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range runs {
			if p.TenantID == tid {
				return p.Kind
			}
		}
		return ""
	}

	t.Run("a tenant never built is pending its first build", func(t *testing.T) {
		if k := pendingKind(t, tenant); k != dashboardfact.RunInitial {
			t.Fatalf("pending kind %q, want initial", k)
		}
		runToEnd(ctx, t, repo, tenant, dashboardfact.RunInitial)
		if d := symmetricDiff(ctx, t, db, factStateSQL, directStateSQL(), tenant.String()); d != 0 {
			t.Fatalf("first build: F1 differs in %d rows", d)
		}
		if k := pendingKind(t, tenant); k != "" {
			t.Fatalf("still pending %q after the first build", k)
		}
		if n := factCount(ctx, t, db, `SELECT count(*) FROM dash_asset_state WHERE tenant_id = $1`, other.String()); n != 0 {
			t.Fatalf("one tenant's run wrote %d rows of another", n)
		}
	})

	t.Run("correct facts reconcile with zero drift", func(t *testing.T) {
		if drift := runToEnd(ctx, t, repo, tenant, dashboardfact.RunNightly); drift != 0 {
			t.Fatalf("drift %d on correct facts", drift)
		}
	})

	t.Run("a marked change is not drift", func(t *testing.T) {
		if _, err := db.ExecContext(ctx, `UPDATE findings SET severity = 'critical' WHERE tenant_id = $1 AND asset_id = $2`,
			tenant.String(), assets[0].String()); err != nil {
			t.Fatal(err)
		}
		if drift := runToEnd(ctx, t, repo, tenant, dashboardfact.RunNightly); drift != 0 {
			t.Fatalf("a change with a pending mark counted as drift: %d", drift)
		}
		clearDirty(ctx, t, db, tenant)
	})

	t.Run("unmarked fact changes are drift and are fixed", func(t *testing.T) {
		if _, err := db.ExecContext(ctx, `UPDATE dash_asset_state SET finding_count = finding_count + 5
			WHERE tenant_id = $1 AND asset_id = $2 AND lens = 'open'`, tenant.String(), assets[1].String()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM dash_asset_rank WHERE tenant_id = $1 AND asset_id = $2`,
			tenant.String(), assets[0].String()); err != nil {
			t.Fatal(err)
		}
		// Facts of an asset that no longer exists.
		if _, err := db.ExecContext(ctx, `INSERT INTO dash_asset_state (tenant_id, asset_id, lens, severity, priority_class,
			sla_state, source, kev, reachable, age_band, pentest_campaign_id, finding_count)
			VALUES ($1, $2, 'open', 'high', 'P1', 'ok', 'sast', false, false, '0-30', '00000000-0000-0000-0000-000000000000', 1)`,
			tenant.String(), shared.NewID().String()); err != nil {
			t.Fatal(err)
		}
		drift := runToEnd(ctx, t, repo, tenant, dashboardfact.RunNightly)
		if drift < 3 {
			t.Fatalf("drift %d, want at least 3", drift)
		}
		if d := symmetricDiff(ctx, t, db, factStateSQL, directStateSQL(), tenant.String()); d != 0 {
			t.Fatalf("drift not fixed: F1 differs in %d rows", d)
		}
		st, err := repo.Status(ctx, tenant, time.Hour)
		if err != nil || st.LastDrift == nil || *st.LastDrift != drift || st.ReconciledAt == nil {
			t.Fatalf("status after the run: %+v (%v), want last_drift %d", st, err, drift)
		}
	})

	t.Run("an age band crossed since the last marking is not drift", func(t *testing.T) {
		a := seedOwnedAsset(ctx, t, db, tenant, nil)
		seedFactFinding(ctx, t, db, tenant, factFinding{asset: &a, severity: "high", priority: "P1", status: "new",
			slaStatus: "on_track", source: "sast", detectedAgo: "35 days"})
		drainFacts(ctx, t, repo, tenant)
		// The fact as it was computed before the finding turned 31 days old.
		stale := `UPDATE dash_asset_state SET age_band = '0-30' WHERE tenant_id = $1 AND asset_id = $2`
		if _, err := db.ExecContext(ctx, stale, tenant.String(), a.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE dash_fact_status SET aged_marked_at = now() - interval '10 days', rebuilt_at = now() - interval '10 days' WHERE tenant_id = $1`, tenant.String()); err != nil {
			t.Fatal(err)
		}
		if drift := runToEnd(ctx, t, repo, tenant, dashboardfact.RunNightly); drift != 0 {
			t.Fatalf("an unmarked age-band crossing counted as drift: %d", drift)
		}
		// The same stale fact after a marking that should have caught it is drift.
		if _, err := db.ExecContext(ctx, stale, tenant.String(), a.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE dash_fact_status SET aged_marked_at = now() WHERE tenant_id = $1`, tenant.String()); err != nil {
			t.Fatal(err)
		}
		if drift := runToEnd(ctx, t, repo, tenant, dashboardfact.RunNightly); drift == 0 {
			t.Fatal("a stale age band after the marking was not counted as drift")
		}
	})

	t.Run("a requested rebuild comes before nightly runs and is rate limited", func(t *testing.T) {
		if _, err := repo.RequestRebuild(ctx, tenant, time.Hour); err != nil {
			t.Fatalf("first request: %v", err)
		}
		if k := pendingKind(t, tenant); k != dashboardfact.RunRequested {
			t.Fatalf("pending kind %q, want requested", k)
		}
		_, err := repo.RequestRebuild(ctx, tenant, time.Hour)
		tooSoon, ok := dashboardfact.AsTooSoon(err)
		if !ok || !errors.Is(err, dashboardfact.ErrRebuildTooSoon) || time.Until(tooSoon.RetryAt) < 59*time.Minute {
			t.Fatalf("second request: %v, want too soon with about an hour to wait", err)
		}
		// Another tenant has its own limit.
		if _, err := repo.RequestRebuild(ctx, other, time.Hour); err != nil {
			t.Fatalf("other tenant's request: %v", err)
		}
		st, err := repo.Status(ctx, tenant, time.Hour)
		if err != nil || !st.Pending || st.NextRebuildAt == nil {
			t.Fatalf("status: %+v (%v)", st, err)
		}
		runToEnd(ctx, t, repo, tenant, dashboardfact.RunRequested)
		if k := pendingKind(t, tenant); k != "" {
			t.Fatalf("still pending %q after the requested run", k)
		}
	})

	t.Run("concurrent requests: exactly one is accepted", func(t *testing.T) {
		tid := seedTestTenant(ctx, t, db)
		var wg sync.WaitGroup
		var mu sync.Mutex
		accepted, refused := 0, 0
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := repo.RequestRebuild(ctx, tid, time.Hour)
				mu.Lock()
				defer mu.Unlock()
				if err == nil {
					accepted++
				} else if errors.Is(err, dashboardfact.ErrRebuildTooSoon) {
					refused++
				} else {
					t.Errorf("request: %v", err)
				}
			}()
		}
		wg.Wait()
		if accepted != 1 || refused != 7 {
			t.Fatalf("accepted %d, refused %d; want 1 and 7", accepted, refused)
		}
	})
}

// F2 partitions and retention, on a private database (the test creates and
// drops partitions).
func TestDashboardFactsMaintainer_Partitions_DB(t *testing.T) {
	ctx := context.Background()
	dir := "../../../migrations"
	db := testdb.PrivateDatabase(t, "dash_maint", dir)
	repo := NewDashboardFactsRepository(&DB{DB: db})
	tenant := shared.NewID()
	if _, err := db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'maint', $2)`, tenant.String(), "maint-"+tenant.String()); err != nil {
		t.Fatal(err)
	}
	asset := shared.NewID()

	// An expired month, a future month missing with a row parked in the
	// default partition, and an expired row in the default partition.
	var future, expiredDay string
	if err := db.QueryRow(`SELECT to_char(date_trunc('month', now()) + interval '5 months', 'YYYY_MM'),
		(dash_history_start() - interval '40 days')::date::text`).Scan(&future, &expiredDay); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`SELECT dash_asset_day_ensure_partitions((dash_history_start() - interval '3 months')::date, 1)`,
		`DROP TABLE dash_asset_day_` + future,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	for _, day := range []string{"(date_trunc('month', now()) + interval '5 months 3 days')::date", "'" + expiredDay + "'::date"} {
		if _, err := db.Exec(`INSERT INTO dash_asset_day (tenant_id, day, asset_id, severity, priority_class, pentest_campaign_id, opened)
			VALUES ($1, `+day+`, $2, 'high', 'P1', '00000000-0000-0000-0000-000000000000', 1)`, tenant.String(), asset.String()); err != nil {
			t.Fatal(err)
		}
	}

	created, dropped, moved, err := repo.MaintainPartitionsForPlatform(ctx)
	if err != nil {
		t.Fatalf("maintain: %v", err)
	}
	if created != 1 || dropped < 1 || moved != 1 {
		t.Fatalf("created %d, dropped %d, moved %d; want 1, >=1, 1", created, dropped, moved)
	}
	n := 0
	_ = db.QueryRow(`SELECT count(*) FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
		WHERE i.inhparent = 'dash_asset_day'::regclass AND c.relname ~ '^dash_asset_day_[0-9]'
		AND to_date(substring(c.relname from '[0-9]{4}_[0-9]{2}$'), 'YYYY_MM') < dash_history_start() - interval '1 month'`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d partitions past the history window remain", n)
	}
	_ = db.QueryRow(`SELECT count(*) FROM dash_asset_day_default`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d rows left in the default partition", n)
	}
	_ = db.QueryRow(`SELECT count(*) FROM dash_dirty_assets WHERE tenant_id = $1 AND asset_id = $2 AND reasons = 1`, tenant.String(), asset.String()).Scan(&n)
	if n != 1 {
		t.Fatalf("the moved row's asset is not marked (%d marks)", n)
	}
	// Idempotent.
	if c, d, m, err := repo.MaintainPartitionsForPlatform(ctx); err != nil || c+d+m != 0 {
		t.Fatalf("second run: %d %d %d (%v)", c, d, m, err)
	}
}

func TestDashboardFactsMaintainerMigration_DB(t *testing.T) {
	dir := "../../../migrations"
	db := testdb.PrivateDatabase(t, "dash_maint_mig", dir)
	v := testdb.MigrationVersion(t, dir, "dashboard_facts_maintainer")
	funcs := func() int {
		var n int
		_ = db.QueryRow(`SELECT count(*) FROM pg_proc WHERE proname IN ('dash_process_dirty', 'dash_reconcile_asset',
			'dash_fact_run_step', 'dash_asset_day_maintain') AND pronamespace = 'public'::regnamespace`).Scan(&n)
		return n
	}
	if n := funcs(); n != 4 {
		t.Fatalf("after up: %d functions", n)
	}
	testdb.Migrate(t, db, dir, v, math.MaxInt32, true)
	var cols int
	_ = db.QueryRow(`SELECT count(*) FROM information_schema.columns WHERE table_name = 'dash_fact_status'
		AND column_name IN ('rebuild_requested_at', 'run_kind', 'run_cursor', 'reconciled_at', 'last_drift')`).Scan(&cols)
	if n := funcs(); n != 0 || cols != 0 {
		t.Fatalf("after down: %d functions, %d columns left", n, cols)
	}
	testdb.Migrate(t, db, dir, v, math.MaxInt32, false)
	if n := funcs(); n != 4 {
		t.Fatalf("after up again: %d functions", n)
	}
}
