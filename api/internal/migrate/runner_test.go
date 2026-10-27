package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/testdb"
)

// fixture is a migrations directory of numbered files that log their runs
// into run_log, so a test sees what ran and in which order.
type fixture struct {
	t   *testing.T
	dir string
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{t: t, dir: t.TempDir()}
	f.add(1, "create_log", `CREATE TABLE run_log (id bigserial PRIMARY KEY, v bigint NOT NULL);`, `DROP TABLE run_log;`)
	return f
}

func (f *fixture) add(v int64, name, up, down string) {
	stem := fmt.Sprintf("%06d_%s", v, name)
	write(f.t, f.dir, stem+".up.sql", up)
	if down != "" {
		write(f.t, f.dir, stem+".down.sql", down)
	}
}

// logged adds a migration that appends its version to run_log.
func (f *fixture) logged(v int64) {
	f.add(v, fmt.Sprintf("m%d", v),
		fmt.Sprintf(`INSERT INTO run_log (v) VALUES (%d);`, v),
		fmt.Sprintf(`INSERT INTO run_log (v) VALUES (-%d);`, v))
}

// released writes released.json with one release that shipped versions.
func (f *fixture) released(versions ...int64) {
	body, err := json.Marshal(map[string]any{"releases": []Release{{Tags: []string{"v0.0.1"}, Versions: versions}}})
	if err != nil {
		f.t.Fatal(err)
	}
	write(f.t, f.dir, ReleasedFile, string(body))
}

func (f *fixture) runner(db *sql.DB) *Runner {
	f.t.Helper()
	ms, err := Load(f.dir)
	if err != nil {
		f.t.Fatal(err)
	}
	rels, err := LoadReleases(f.dir)
	if err != nil {
		f.t.Fatal(err)
	}
	return &Runner{DB: db, Migrations: ms, Takeover: Takeover{Releases: rels}, LockTimeout: 5 * time.Second, Logf: f.t.Logf}
}

// assuming is f.runner with an operator's list of applied versions.
func (f *fixture) assuming(db *sql.DB, versions ...int64) *Runner {
	r := f.runner(db)
	r.Takeover.AssumeApplied = map[int64]bool{}
	for _, v := range versions {
		r.Takeover.AssumeApplied[v] = true
	}
	return r
}

func runLog(t *testing.T, db *sql.DB) []int64 {
	t.Helper()
	rows, err := db.Query(`SELECT v FROM run_log ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := []int64{}
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func applied(t *testing.T, db *sql.DB) []int64 {
	t.Helper()
	rows, err := db.Query(`SELECT version FROM schema_migrations_applied ORDER BY version`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := []int64{}
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func tracker(t *testing.T, db *sql.DB) (int64, bool) {
	t.Helper()
	var v int64
	var dirty bool
	if err := db.QueryRow(`SELECT version, dirty FROM schema_migrations`).Scan(&v, &dirty); err != nil {
		t.Fatal(err)
	}
	return v, dirty
}

func eq(t *testing.T, what string, got, want []int64) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s = %v, want %v", what, got, want)
	}
}

func TestUpFreshThenIdempotent(t *testing.T) {
	db := testdb.EmptyDatabase(t, "migrate_up")
	f := newFixture(t)
	f.logged(2)
	f.logged(3)
	ctx := context.Background()
	res, err := f.runner(db).Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "applied now", versionsOf(res.Applied), []int64{1, 2, 3})
	eq(t, "run log", runLog(t, db), []int64{2, 3})
	eq(t, "applied set", applied(t, db), []int64{1, 2, 3})
	// Clean: schema_migrations holds the fence an older migrations image refuses.
	if v, dirty := tracker(t, db); v != Fence || dirty {
		t.Fatalf("tracker = %d dirty=%v, want the fence", v, dirty)
	}

	res, err = f.runner(db).Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Applied) != 0 || len(res.Recorded) != 0 {
		t.Fatalf("second run changed something: %+v", res)
	}
	eq(t, "run log after the second run", runLog(t, db), []int64{2, 3})
}

// The case this runner exists for: a migration merged after a higher
// version was applied runs on the next up instead of being skipped.
func TestUpAppliesMissingInMiddle(t *testing.T) {
	db := testdb.EmptyDatabase(t, "migrate_mid")
	f := newFixture(t)
	f.logged(3)
	f.logged(5)
	ctx := context.Background()
	if _, err := f.runner(db).Up(ctx); err != nil {
		t.Fatal(err)
	}
	f.logged(2)
	f.logged(4)
	f.logged(6)
	rep, err := Inspect(ctx, db, f.runner(db).Migrations, Takeover{})
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "pending before", versionsOf(rep.Pending), []int64{2, 4, 6})

	res, err := f.runner(db).Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "applied now", versionsOf(res.Applied), []int64{2, 4, 6})
	eq(t, "run log", runLog(t, db), []int64{3, 5, 2, 4, 6})
	eq(t, "applied set", applied(t, db), []int64{1, 2, 3, 4, 5, 6})
	if v, dirty := tracker(t, db); v != Fence || dirty {
		t.Fatalf("tracker = %d dirty=%v", v, dirty)
	}
}

func TestDirtyRefusalAndForce(t *testing.T) {
	db := testdb.EmptyDatabase(t, "migrate_dirty")
	f := newFixture(t)
	f.logged(2)
	f.add(3, "broken", `INSERT INTO run_log (v) VALUES (3); SELECT * FROM no_such_table;`, `SELECT 1;`)
	f.logged(4)
	ctx := context.Background()

	if _, err := f.runner(db).Up(ctx); err == nil {
		t.Fatal("up succeeded over a failing migration")
	}
	if v, dirty := tracker(t, db); v != 3 || !dirty {
		t.Fatalf("tracker = %d dirty=%v, want 3 dirty", v, dirty)
	}
	// The file ran in one implicit transaction: its first insert is gone.
	eq(t, "run log", runLog(t, db), []int64{2})

	// Dirty: nothing else runs, not even migrations above the failed one.
	_, err := f.runner(db).Up(ctx)
	var d ErrDirty
	if !errors.As(err, &d) || d.Version != 3 {
		t.Fatalf("second up: %v, want ErrDirty{3}", err)
	}
	eq(t, "run log after refusal", runLog(t, db), []int64{2})
	if _, err := f.runner(db).Down(ctx, 1); !errors.As(err, &d) {
		t.Fatalf("down on a dirty database: %v, want ErrDirty", err)
	}

	// force -1 clears the flag and leaves 3 pending; fixed, up runs it.
	if err := f.runner(db).Force(ctx, -1); err != nil {
		t.Fatal(err)
	}
	if v, dirty := tracker(t, db); v != Fence || dirty {
		t.Fatalf("tracker after force -1 = %d dirty=%v", v, dirty)
	}
	f.add(3, "broken", `INSERT INTO run_log (v) VALUES (3);`, `SELECT 1;`)
	if _, err := f.runner(db).Up(ctx); err != nil {
		t.Fatal(err)
	}
	eq(t, "run log after the fix", runLog(t, db), []int64{2, 3, 4})
	eq(t, "applied set", applied(t, db), []int64{1, 2, 3, 4})
}

func TestForceRecordsWithoutRunning(t *testing.T) {
	db := testdb.EmptyDatabase(t, "migrate_force")
	f := newFixture(t)
	f.add(2, "fails", `SELECT * FROM no_such_table;`, `SELECT 1;`)
	f.logged(3)
	ctx := context.Background()
	if _, err := f.runner(db).Up(ctx); err == nil {
		t.Fatal("expected the failure")
	}
	// An operator finished 2 by hand: force 2 records it, up continues.
	if err := f.runner(db).Force(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := f.runner(db).Up(ctx); err != nil {
		t.Fatal(err)
	}
	eq(t, "applied set", applied(t, db), []int64{1, 2, 3})
	eq(t, "run log", runLog(t, db), []int64{3})
	if err := f.runner(db).Force(ctx, 99); err == nil {
		t.Fatal("force of a version with no file succeeded")
	}
}

func TestConcurrentRunnersApplyEachMigrationOnce(t *testing.T) {
	db := testdb.EmptyDatabase(t, "migrate_lock")
	f := newFixture(t)
	f.add(2, "slow", `SELECT pg_sleep(0.5); INSERT INTO run_log (v) VALUES (2);`, `SELECT 1;`)
	f.logged(3)
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make([]error, 3)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = f.runner(db).Up(ctx)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("runner %d: %v", i, err)
		}
	}
	eq(t, "run log", runLog(t, db), []int64{2, 3})
	eq(t, "applied set", applied(t, db), []int64{1, 2, 3})
}

func TestLockTimeout(t *testing.T) {
	db := testdb.EmptyDatabase(t, "migrate_lockto")
	f := newFixture(t)
	ctx := context.Background()
	holder, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close() }()
	var name, schema string
	if err := holder.QueryRowContext(ctx, `SELECT current_database(), current_schema()`).Scan(&name, &schema); err != nil {
		t.Fatal(err)
	}
	// Held as the earlier tool holds it: same key.
	if _, err := holder.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, LockKey(name, schema)); err != nil {
		t.Fatal(err)
	}
	r := f.runner(db)
	r.LockTimeout = 400 * time.Millisecond
	if _, err := r.Up(ctx); !errors.Is(err, ErrLockTimeout) {
		t.Fatalf("up under a held lock: %v, want ErrLockTimeout", err)
	}
	if ok, _ := tableExists(ctx, db, "public", appliedTable); ok {
		t.Fatal("a run without the lock touched the database")
	}
}

// A database the earlier tool migrated: schema_migrations only, at version
// 3. Files up to 3 are recorded, not run again; the rest run.
func TestBackfillFromEarlierToolState(t *testing.T) {
	db := testdb.EmptyDatabase(t, "migrate_backfill")
	f := newFixture(t)
	f.logged(2)
	f.logged(3)
	f.logged(4)
	f.released(1, 2, 3)
	ctx := context.Background()
	for _, q := range []string{
		`CREATE TABLE schema_migrations (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL)`,
		`CREATE TABLE run_log (id bigserial PRIMARY KEY, v bigint NOT NULL)`,
		`INSERT INTO run_log (v) VALUES (2), (3)`,
		`INSERT INTO schema_migrations VALUES (3, false)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := Inspect(ctx, db, f.runner(db).Migrations, f.runner(db).Takeover)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "pending before", versionsOf(rep.Pending), []int64{4})

	res, err := f.runner(db).Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "recorded", versionsOf(res.Recorded), []int64{1, 2, 3})
	eq(t, "applied now", versionsOf(res.Applied), []int64{4})
	eq(t, "run log", runLog(t, db), []int64{2, 3, 4})
	eq(t, "applied set", applied(t, db), []int64{1, 2, 3, 4})

	if v, _ := tracker(t, db); v != Fence {
		t.Fatalf("tracker after the takeover = %d, want the fence", v)
	}

	// Someone forces the earlier tool past the fence and it applies 5: the
	// runner refuses until an operator records what that tool did.
	f.logged(5)
	if _, err := db.Exec(`INSERT INTO run_log (v) VALUES (5); UPDATE schema_migrations SET version = 5`); err != nil {
		t.Fatal(err)
	}
	f.logged(6)
	var m ErrTrackerMismatch
	if _, err := f.runner(db).Up(ctx); !errors.As(err, &m) || m.Tracker != 5 {
		t.Fatalf("up after the earlier tool: %v, want ErrTrackerMismatch{5}", err)
	}
	if err := f.runner(db).Force(ctx, 5); err != nil {
		t.Fatal(err)
	}
	res, err = f.runner(db).Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "applied after force", versionsOf(res.Applied), []int64{6})
	eq(t, "run log", runLog(t, db), []int64{2, 3, 4, 5, 6})
}

// The earlier tool migrated a development database past timestamp versions
// (it skips one merged after a higher one): no release ends at its version,
// so the runner refuses until an operator lists what is applied.
func TestTakeoverWithoutAMatchingReleaseRefuses(t *testing.T) {
	db := testdb.EmptyDatabase(t, "migrate_undecided")
	f := newFixture(t)
	f.logged(2)
	f.logged(20261027000001)
	f.logged(20261027000003)
	f.logged(20261027000002) // merged last, skipped by the earlier tool
	f.released(1, 2)
	ctx := context.Background()
	for _, q := range []string{
		`CREATE TABLE schema_migrations (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL)`,
		`CREATE TABLE run_log (id bigserial PRIMARY KEY, v bigint NOT NULL)`,
		`INSERT INTO run_log (v) VALUES (2), (20261027000001), (20261027000003)`,
		`INSERT INTO schema_migrations VALUES (20261027000003, false)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	var u ErrUndecidedTakeover
	if _, err := f.runner(db).Up(ctx); !errors.As(err, &u) || u.Tracker != 20261027000003 {
		t.Fatalf("up: %v, want ErrUndecidedTakeover", err)
	}
	if err := f.runner(db).Force(ctx, -1); !errors.As(err, &u) {
		t.Fatalf("force -1 without a list: %v, want ErrUndecidedTakeover", err)
	}
	eq(t, "run log after the refusals", runLog(t, db), []int64{2, 20261027000001, 20261027000003})
	eq(t, "applied set after the refusals", applied(t, db), []int64{})

	res, err := f.assuming(db, 1, 2, 20261027000001, 20261027000003).Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "recorded", versionsOf(res.Recorded), []int64{1, 2, 20261027000001, 20261027000003})
	eq(t, "applied now", versionsOf(res.Applied), []int64{20261027000002})
	eq(t, "applied set", applied(t, db), []int64{1, 2, 20261027000001, 20261027000002, 20261027000003})
}

// A database a release migrated (v0.15.4: up to 003428) lacks a migration
// merged to develop afterwards with a lower number (003420). The takeover
// records only that release's files; 003420 stays pending and up runs it.
func TestTakeoverLeavesALateLowerMigrationPending(t *testing.T) {
	db := testdb.EmptyDatabase(t, "migrate_late")
	f := newFixture(t)
	f.logged(3419)
	f.logged(3420) // merged after the release, below its last migration
	f.logged(3428)
	f.logged(20261027000001)
	f.released(1, 3419, 3428)
	ctx := context.Background()
	for _, q := range []string{
		`CREATE TABLE schema_migrations (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL)`,
		`CREATE TABLE run_log (id bigserial PRIMARY KEY, v bigint NOT NULL)`,
		`INSERT INTO run_log (v) VALUES (3419), (3428)`,
		`INSERT INTO schema_migrations VALUES (3428, false)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := Inspect(ctx, db, f.runner(db).Migrations, f.runner(db).Takeover)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "pending before", versionsOf(rep.Pending), []int64{3420, 20261027000001})
	res, err := f.runner(db).Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "recorded", versionsOf(res.Recorded), []int64{1, 3419, 3428})
	eq(t, "applied now", versionsOf(res.Applied), []int64{3420, 20261027000001})
	eq(t, "run log", runLog(t, db), []int64{3419, 3428, 3420, 20261027000001})
}

func TestBackfillOfDirtyEarlierToolStateRefuses(t *testing.T) {
	db := testdb.EmptyDatabase(t, "migrate_bfdirty")
	f := newFixture(t)
	f.logged(2)
	f.logged(3)
	f.released(1, 2, 3)
	ctx := context.Background()
	for _, q := range []string{
		`CREATE TABLE schema_migrations (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL)`,
		`CREATE TABLE run_log (id bigserial PRIMARY KEY, v bigint NOT NULL)`,
		`INSERT INTO schema_migrations VALUES (2, true)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	var d ErrDirty
	if _, err := f.runner(db).Up(ctx); !errors.As(err, &d) || d.Version != 2 || !d.EarlierTool {
		t.Fatalf("up: %v, want ErrDirty{2, earlier tool}", err)
	}
	// Which migrations below 2 ran is unknown: force needs the list.
	var u ErrUndecidedTakeover
	if err := f.runner(db).Force(ctx, -1); !errors.As(err, &u) || !u.Dirty {
		t.Fatalf("force -1 without a list: %v, want ErrUndecidedTakeover (dirty)", err)
	}
	if err := f.assuming(db, 1).Force(ctx, -1); err != nil {
		t.Fatal(err)
	}
	eq(t, "applied set after force", applied(t, db), []int64{1})
	if _, err := f.runner(db).Up(ctx); err != nil {
		t.Fatal(err)
	}
	eq(t, "run log", runLog(t, db), []int64{2, 3})
}

// Down undoes the most recently applied migration, which after an
// apply-missing run is not the highest version.
func TestDownRollsBackMostRecentlyApplied(t *testing.T) {
	db := testdb.EmptyDatabase(t, "migrate_down")
	f := newFixture(t)
	f.logged(3)
	ctx := context.Background()
	if _, err := f.runner(db).Up(ctx); err != nil {
		t.Fatal(err)
	}
	f.logged(2)
	if _, err := f.runner(db).Up(ctx); err != nil {
		t.Fatal(err)
	}
	done, err := f.runner(db).Down(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "rolled back", versionsOf(done), []int64{2})
	eq(t, "applied set", applied(t, db), []int64{1, 3})
	if v, dirty := tracker(t, db); v != Fence || dirty {
		t.Fatalf("tracker = %d dirty=%v", v, dirty)
	}
	// Up, down, up again.
	if _, err := f.runner(db).Up(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.runner(db).Down(ctx, 4); err != nil {
		t.Fatal(err)
	}
	if ok, _ := tableExists(ctx, db, "public", "run_log"); ok {
		t.Fatal("down of everything left run_log")
	}
	if _, err := f.runner(db).Up(ctx); err != nil {
		t.Fatal(err)
	}
	eq(t, "applied set after up again", applied(t, db), []int64{1, 2, 3})
}

func TestRefusalsChangeNothing(t *testing.T) {
	ctx := context.Background()
	t.Run("tracker rolled back by another tool", func(t *testing.T) {
		db := testdb.EmptyDatabase(t, "migrate_mismatch")
		f := newFixture(t)
		f.logged(2)
		if _, err := f.runner(db).Up(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`UPDATE schema_migrations SET version = 1`); err != nil {
			t.Fatal(err)
		}
		f.logged(3)
		var m ErrTrackerMismatch
		if _, err := f.runner(db).Up(ctx); !errors.As(err, &m) {
			t.Fatalf("up: %v, want ErrTrackerMismatch", err)
		}
		eq(t, "run log", runLog(t, db), []int64{2})
	})
	t.Run("newer database", func(t *testing.T) {
		db := testdb.EmptyDatabase(t, "migrate_newer")
		f := newFixture(t)
		f.logged(2)
		f.logged(3)
		if _, err := f.runner(db).Up(ctx); err != nil {
			t.Fatal(err)
		}
		older := newFixture(t)
		older.logged(2)
		var n ErrNewerDatabase
		if _, err := older.runner(db).Up(ctx); !errors.As(err, &n) || n.Applied != 3 {
			t.Fatalf("up of an older release: %v, want ErrNewerDatabase{3}", err)
		}
	})
	t.Run("older than the baseline", func(t *testing.T) {
		db := testdb.EmptyDatabase(t, "migrate_baseline")
		f := &fixture{t: t, dir: t.TempDir()}
		f.add(100, "baseline", `CREATE TABLE run_log (id bigserial PRIMARY KEY, v bigint NOT NULL);`, `DO $$ BEGIN RAISE EXCEPTION 'no'; END $$;`)
		f.logged(110)
		for _, q := range []string{
			`CREATE TABLE schema_migrations (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL)`,
			`INSERT INTO schema_migrations VALUES (50, false)`,
		} {
			if _, err := db.Exec(q); err != nil {
				t.Fatal(err)
			}
		}
		var b ErrOlderThanBaseline
		if _, err := f.runner(db).Up(ctx); !errors.As(err, &b) || b.Version != 50 || b.Baseline != 100 {
			t.Fatalf("up: %v, want ErrOlderThanBaseline{50, 100}", err)
		}
		if ok, _ := tableExists(ctx, db, "public", "run_log"); ok {
			t.Fatal("the baseline ran on a database older than it")
		}
	})
}

// The earlier tool failed at T2 after applying T1 (dirty T2, T1 applied, no
// recorded versions). force -1 used to record only the legacy files and
// clear the flag, so the next up ran T1 again. Without the operator's list
// force refuses (-1 and T2 alike); with it, up runs only T2.
func TestForceOnDirtyEarlierToolStateNeedsTheAppliedList(t *testing.T) {
	db := testdb.EmptyDatabase(t, "migrate_dirtyundecided")
	f := newFixture(t)
	f.logged(2)
	const t1, t2 = 20261027000001, 20261027000002
	// T1 creates a table without IF NOT EXISTS: running it twice fails.
	f.add(t1, "create_once", `CREATE TABLE once_only (id int); INSERT INTO run_log (v) VALUES (20261027000001);`, `DROP TABLE once_only;`)
	f.logged(t2)
	f.released(1, 2)
	ctx := context.Background()
	for _, q := range []string{
		`CREATE TABLE schema_migrations (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL)`,
		`CREATE TABLE run_log (id bigserial PRIMARY KEY, v bigint NOT NULL)`,
		`CREATE TABLE once_only (id int)`,
		`INSERT INTO run_log (v) VALUES (2), (20261027000001)`,
		`INSERT INTO schema_migrations VALUES (20261027000002, true)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	var d ErrDirty
	if _, err := f.runner(db).Up(ctx); !errors.As(err, &d) || !d.EarlierTool {
		t.Fatalf("up: %v, want ErrDirty from the earlier tool", err)
	}
	for _, v := range []int64{-1, t1, t2} {
		var u ErrUndecidedTakeover
		if err := f.runner(db).Force(ctx, v); !errors.As(err, &u) || !u.Dirty {
			t.Fatalf("force %d: %v, want ErrUndecidedTakeover (dirty)", v, err)
		}
		eq(t, "applied set after the refused force", applied(t, db), []int64{})
		if tv, dirty := tracker(t, db); tv != t2 || !dirty {
			t.Fatalf("tracker after the refused force = (%d, %v), want (%d, true)", tv, dirty, t2)
		}
	}

	if err := f.assuming(db, 1, 2, t1).Force(ctx, -1); err != nil {
		t.Fatal(err)
	}
	res, err := f.runner(db).Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "applied now", versionsOf(res.Applied), []int64{t2})
	eq(t, "run log", runLog(t, db), []int64{2, t1, t2})
	eq(t, "applied set", applied(t, db), []int64{1, 2, t1, t2})
}

// A migration that changes search_path for the session must not redirect
// the records: they go to the schema the run locked.
func TestRecordsStayInTheLockedSchema(t *testing.T) {
	db := testdb.EmptyDatabase(t, "migrate_searchpath")
	f := newFixture(t)
	f.add(2, "elsewhere", `CREATE SCHEMA elsewhere; SET search_path TO elsewhere;`, `DROP SCHEMA elsewhere;`)
	f.add(3, "after", `INSERT INTO public.run_log (v) VALUES (3);`, ``)
	ctx := context.Background()
	// One connection, so the run's session is the one checked (no other
	// pooled connection with the default search_path).
	db.SetMaxOpenConns(1)
	if _, err := f.runner(db).Up(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	var v int64
	var dirty bool
	if err := db.QueryRow(`SELECT count(*) FROM public.schema_migrations_applied`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("recorded in public: %d (%v), want 3", n, err)
	}
	if err := db.QueryRow(`SELECT version, dirty FROM public.schema_migrations`).Scan(&v, &dirty); err != nil || v != Fence || dirty {
		t.Fatalf("tracker = (%d, %v, %v), want the fence", v, dirty, err)
	}
	var stray bool
	if err := db.QueryRow(`SELECT to_regclass('elsewhere.schema_migrations_applied') IS NOT NULL`).Scan(&stray); err != nil {
		t.Fatal(err)
	}
	if stray {
		t.Fatal("a tracking table was created in the schema a migration switched to")
	}
}

// An install whose roles script ran before the runner created its tables:
// the migrator's default privileges hand the app role (and here PUBLIC)
// full DML on them. The run must take every write back, keeping SELECT.
func TestTrackingTablesWritableOnlyByOwner(t *testing.T) {
	admin, err := sql.Open("postgres", testdb.AdminURL())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	role := fmt.Sprintf("migrate_app_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE ROLE ` + role + ` NOLOGIN`); err != nil {
		t.Skipf("cannot create a role: %v", err)
	}
	// Runs after the private database is dropped (cleanups run last-in first-out).
	t.Cleanup(func() {
		a, err := sql.Open("postgres", testdb.AdminURL())
		if err == nil {
			_, _ = a.Exec(`DROP ROLE IF EXISTS ` + role)
			_ = a.Close()
		}
	})
	db := testdb.EmptyDatabase(t, "migrate_owneronly")
	if _, err := db.Exec(`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON TABLES TO ` + role + `, PUBLIC`); err != nil {
		t.Fatal(err)
	}
	f := newFixture(t)
	f.logged(2)
	if _, err := f.runner(db).Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"schema_migrations", "schema_migrations_applied"} {
		for _, priv := range []string{"INSERT", "UPDATE", "DELETE", "TRUNCATE"} {
			var can bool
			if err := db.QueryRow(`SELECT has_table_privilege($1, $2, $3)`, role, table, priv).Scan(&can); err != nil {
				t.Fatal(err)
			}
			if can {
				t.Errorf("%s may %s %s", role, priv, table)
			}
			var public int
			if err := db.QueryRow(`SELECT count(*) FROM aclexplode((SELECT relacl FROM pg_class WHERE oid = $1::regclass)) a
				WHERE a.grantee = 0 AND a.privilege_type = $2`, table, priv).Scan(&public); err != nil {
				t.Fatal(err)
			}
			if public > 0 {
				t.Errorf("PUBLIC may %s %s", priv, table)
			}
		}
		var read bool
		if err := db.QueryRow(`SELECT has_table_privilege($1, $2, 'SELECT')`, role, table).Scan(&read); err != nil {
			t.Fatal(err)
		}
		if !read {
			t.Errorf("%s lost SELECT on %s", role, table)
		}
	}
	// An application table created by a migration keeps its default grants.
	var can bool
	if err := db.QueryRow(`SELECT has_table_privilege($1, 'run_log', 'INSERT')`, role).Scan(&can); err != nil {
		t.Fatal(err)
	}
	if !can {
		t.Error("the revoke reached an application table")
	}
}
