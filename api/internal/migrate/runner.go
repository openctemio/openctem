package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"strings"
	"time"
)

const (
	trackerTable = "schema_migrations"
	appliedTable = "schema_migrations_applied"

	// lockSalt and the key layout below are the ones the earlier migration
	// tool used, so this runner and an older migrations image never migrate
	// one database at the same time.
	lockSalt uint32 = 1486364155

	// DefaultLockTimeout is how long a run waits for another run's lock.
	DefaultLockTimeout = 15 * time.Second
)

// ErrLockTimeout: another run held the migration lock for the whole wait.
var ErrLockTimeout = errors.New("timed out waiting for the migration lock: another migration run is in progress")

// Runner applies, rolls back and records migrations on one database.
type Runner struct {
	DB          *sql.DB
	Migrations  []Migration
	LockTimeout time.Duration        // DefaultLockTimeout when zero
	Logf        func(string, ...any) // progress lines; nil discards them
}

// Result is what a run changed.
type Result struct {
	Recorded []Migration // applied by an earlier tool, recorded now
	Applied  []Migration // run by this call, in order
	Unknown  []int64     // see plan.Unknown
}

func (r *Runner) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

// queryer is what reading the state needs (*sql.DB, *sql.Conn, *sql.Tx).
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// LockKey is the advisory lock key of the migration lock for a database
// and schema.
func LockKey(database, schema string) int64 {
	sum := crc32.ChecksumIEEE([]byte(schema + "\x00" + trackerTable + "\x00" + database))
	return int64(sum * lockSalt)
}

// withLock runs fn on one connection that holds the migration lock (a
// session advisory lock, released when fn returns or the connection dies).
// A waiting run polls pg_try_advisory_lock from an idle session instead of
// blocking in pg_advisory_lock: a blocked statement keeps a snapshot open,
// and CREATE INDEX CONCURRENTLY in the holder's migration waits for every
// open snapshot, which deadlocks the two.
func (r *Runner) withLock(ctx context.Context, fn func(*sql.Conn) error) error {
	conn, err := r.DB.Conn(ctx)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close() }()

	var dbName, schema sql.NullString
	if err := conn.QueryRowContext(ctx, `SELECT current_database(), current_schema()`).Scan(&dbName, &schema); err != nil {
		return fmt.Errorf("read the current schema: %w", err)
	}
	if !schema.Valid {
		return errors.New("the connection has no current schema (check search_path)")
	}
	key := LockKey(dbName.String, schema.String)

	timeout := r.LockTimeout
	if timeout <= 0 {
		timeout = DefaultLockTimeout
	}
	deadline := time.Now().Add(timeout)
	waited := false
	for {
		var got bool
		if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&got); err != nil {
			return fmt.Errorf("take the migration lock: %w", err)
		}
		if got {
			break
		}
		if !waited {
			r.logf("waiting for the migration lock (another run holds it)")
			waited = true
		}
		if time.Now().After(deadline) {
			return ErrLockTimeout
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	defer func() {
		// Not the run's context: the lock must go even when it was cancelled.
		uctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(uctx, `SELECT pg_advisory_unlock($1)`, key)
	}()
	return fn(conn)
}

// ensureTables creates the two tracking tables when they are missing. It
// checks first, so a role without CREATE on the schema works on a database
// that has them (the roles script creates both ahead of the first run).
func ensureTables(ctx context.Context, conn *sql.Conn) error {
	ddl := map[string]string{
		trackerTable: `CREATE TABLE IF NOT EXISTS schema_migrations (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL)`,
		appliedTable: `CREATE TABLE IF NOT EXISTS schema_migrations_applied (
			version bigint NOT NULL PRIMARY KEY,
			name text NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
	}
	for _, t := range []string{trackerTable, appliedTable} {
		exists, err := tableExists(ctx, conn, t)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := conn.ExecContext(ctx, ddl[t]); err != nil {
			return fmt.Errorf("create %s: %w", t, err)
		}
	}
	return nil
}

func tableExists(ctx context.Context, q queryer, table string) (bool, error) {
	var exists bool
	err := q.QueryRowContext(ctx,
		`SELECT to_regclass(quote_ident(current_schema()) || '.' || quote_ident($1)) IS NOT NULL`, table).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("look up %s: %w", table, err)
	}
	return exists, nil
}

// readState reads both tables; a missing table reads as empty.
func readState(ctx context.Context, q queryer) (dbState, error) {
	st := dbState{Applied: map[int64]bool{}}
	if ok, err := tableExists(ctx, q, trackerTable); err != nil {
		return st, err
	} else if ok {
		err := q.QueryRowContext(ctx, `SELECT version, dirty FROM schema_migrations ORDER BY version DESC LIMIT 1`).
			Scan(&st.Tracker, &st.Dirty)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return st, fmt.Errorf("read schema_migrations: %w", err)
		}
		// The earlier tool writes -1 for "nothing applied" after a failed
		// first down migration.
		st.Tracker = max(st.Tracker, 0)
	}
	ok, err := tableExists(ctx, q, appliedTable)
	if err != nil || !ok {
		return st, err
	}
	rows, err := q.QueryContext(ctx, `SELECT version FROM schema_migrations_applied`)
	if err != nil {
		return st, fmt.Errorf("read schema_migrations_applied: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return st, err
		}
		st.Applied[v] = true
	}
	return st, rows.Err()
}

// setTracker writes the single schema_migrations row: (Fence, false) while
// clean, (version, true) while a migration runs.
func setTracker(ctx context.Context, x execer, version int64, dirty bool) error {
	if !dirty {
		version = Fence
	}
	if _, err := x.ExecContext(ctx, `DELETE FROM schema_migrations`); err != nil {
		return fmt.Errorf("write schema_migrations: %w", err)
	}
	if _, err := x.ExecContext(ctx, `INSERT INTO schema_migrations (version, dirty) VALUES ($1, $2)`, version, dirty); err != nil {
		return fmt.Errorf("write schema_migrations: %w", err)
	}
	return nil
}

// markDirty records, before a migration file runs, that it is running: a
// failure or a crash midway leaves the database dirty at that version.
func markDirty(ctx context.Context, conn *sql.Conn, version int64) error {
	return inTx(ctx, conn, func(tx *sql.Tx) error { return setTracker(ctx, tx, version, true) })
}

func inTx(ctx context.Context, conn *sql.Conn, fn func(*sql.Tx) error) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// prepare takes the state under the lock, refuses what resolve refuses and
// records the migrations an earlier tool applied.
func (r *Runner) prepare(ctx context.Context, conn *sql.Conn) (plan, error) {
	if err := ensureTables(ctx, conn); err != nil {
		return plan{}, err
	}
	st, err := readState(ctx, conn)
	if err != nil {
		return plan{}, err
	}
	p, err := resolve(st, r.Migrations)
	if err != nil {
		return p, err
	}
	if len(p.Record) > 0 || st.Tracker != Fence {
		err := inTx(ctx, conn, func(tx *sql.Tx) error {
			for _, m := range p.Record {
				if _, err := tx.ExecContext(ctx,
					`INSERT INTO schema_migrations_applied (version, name) VALUES ($1, $2) ON CONFLICT (version) DO NOTHING`,
					m.Version, m.Name); err != nil {
					return fmt.Errorf("record %s: %w", m.Stem(), err)
				}
			}
			return setTracker(ctx, tx, 0, false)
		})
		if err != nil {
			return p, err
		}
	}
	if len(p.Record) > 0 {
		r.logf("took the database over from the earlier migration tool: recorded its %d migrations up to %d", len(p.Record), st.Tracker)
	}
	for _, v := range p.Unknown {
		r.logf("warning: migration %d is applied but not shipped in this directory", v)
	}
	return p, nil
}

// runFile runs one migration file the way the earlier tool did: the whole
// file as one simple-protocol statement batch (one implicit transaction
// unless the file manages its own).
func runFile(ctx context.Context, conn *sql.Conn, path string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(body)) == "" {
		return nil
	}
	_, err = conn.ExecContext(ctx, string(body))
	return err
}

// Up applies every pending migration, lowest version first. A pending
// migration below the highest applied one (merged after it) is applied
// like any other.
func (r *Runner) Up(ctx context.Context) (Result, error) {
	var res Result
	err := r.withLock(ctx, func(conn *sql.Conn) error {
		p, err := r.prepare(ctx, conn)
		res.Recorded, res.Unknown = p.Record, p.Unknown
		if err != nil {
			return err
		}
		highest := p.Highest
		for _, m := range p.Pending {
			if err := markDirty(ctx, conn, m.Version); err != nil {
				return err
			}
			start := time.Now()
			if err := runFile(ctx, conn, m.UpPath); err != nil {
				return fmt.Errorf("migration %s failed; the database is marked dirty at %d: %w", m.Stem(), m.Version, err)
			}
			highest = max(highest, m.Version)
			err := inTx(ctx, conn, func(tx *sql.Tx) error {
				if _, err := tx.ExecContext(ctx,
					`INSERT INTO schema_migrations_applied (version, name) VALUES ($1, $2)`, m.Version, m.Name); err != nil {
					return fmt.Errorf("record %s: %w", m.Stem(), err)
				}
				return setTracker(ctx, tx, 0, false)
			})
			if err != nil {
				return err
			}
			res.Applied = append(res.Applied, m)
			note := ""
			if m.Version < highest {
				note = fmt.Sprintf(" (below the highest applied version %d: merged after it)", highest)
			}
			r.logf("applied %s in %s%s", m.Stem(), time.Since(start).Round(time.Millisecond), note)
		}
		if len(p.Pending) == 0 {
			r.logf("no change")
		}
		return nil
	})
	return res, err
}

// Down rolls back the n most recently applied migrations, newest first
// (by when they were applied, then by version).
func (r *Runner) Down(ctx context.Context, n int) ([]Migration, error) {
	if n <= 0 {
		return nil, errors.New("down needs the number of migrations to roll back")
	}
	byVersion := make(map[int64]Migration, len(r.Migrations))
	for _, m := range r.Migrations {
		byVersion[m.Version] = m
	}
	var done []Migration
	err := r.withLock(ctx, func(conn *sql.Conn) error {
		if _, err := r.prepare(ctx, conn); err != nil {
			return err
		}
		rows, err := conn.QueryContext(ctx,
			`SELECT version FROM schema_migrations_applied ORDER BY applied_at DESC, version DESC LIMIT $1`, n)
		if err != nil {
			return fmt.Errorf("read schema_migrations_applied: %w", err)
		}
		var versions []int64
		for rows.Next() {
			var v int64
			if err := rows.Scan(&v); err != nil {
				_ = rows.Close()
				return err
			}
			versions = append(versions, v)
		}
		_ = rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, v := range versions {
			m, ok := byVersion[v]
			if !ok || m.DownPath == "" {
				return fmt.Errorf("migration %d has no down file in this directory; nothing more was rolled back", v)
			}
			if err := markDirty(ctx, conn, v); err != nil {
				return err
			}
			if err := runFile(ctx, conn, m.DownPath); err != nil {
				return fmt.Errorf("down migration %s failed; the database is marked dirty at %d: %w", m.Stem(), v, err)
			}
			err := inTx(ctx, conn, func(tx *sql.Tx) error {
				if _, err := tx.ExecContext(ctx, `DELETE FROM schema_migrations_applied WHERE version = $1`, v); err != nil {
					return err
				}
				return setTracker(ctx, tx, 0, false)
			})
			if err != nil {
				return err
			}
			done = append(done, m)
			r.logf("rolled back %s", m.Stem())
		}
		if len(versions) == 0 {
			r.logf("no change")
		}
		return nil
	})
	return done, err
}

// Force clears the dirty flag and records version as applied without
// running it; version -1 records nothing. After a failed migration: force
// its own version when it completed (or was finished by hand), or -1 after
// undoing its partial changes, so the next up runs it again. On a database
// the earlier tool migrated it also records that tool's legacy-numbered
// migrations, as the first up would (the way to settle ErrUndecidedTakeover:
// force each timestamp version that is applied).
func (r *Runner) Force(ctx context.Context, version int64) error {
	var m Migration
	if version != -1 {
		found := false
		for _, x := range r.Migrations {
			if x.Version == version {
				m, found = x, true
				break
			}
		}
		if !found {
			return fmt.Errorf("no migration with version %d in this directory", version)
		}
	}
	return r.withLock(ctx, func(conn *sql.Conn) error {
		if err := ensureTables(ctx, conn); err != nil {
			return err
		}
		st, err := readState(ctx, conn)
		if err != nil {
			return err
		}
		var record []Migration
		if len(st.Applied) == 0 && st.Tracker > 0 && st.Tracker != Fence {
			// The earlier tool's database: below a dirty version, up to a
			// clean one.
			upTo := st.Tracker
			if st.Dirty {
				upTo--
			}
			record, _ = takeover(upTo, r.Migrations)
		}
		if version != -1 {
			record = append(record, m)
		}
		return inTx(ctx, conn, func(tx *sql.Tx) error {
			for _, x := range record {
				if _, err := tx.ExecContext(ctx,
					`INSERT INTO schema_migrations_applied (version, name) VALUES ($1, $2) ON CONFLICT (version) DO NOTHING`,
					x.Version, x.Name); err != nil {
					return err
				}
			}
			if st.Dirty {
				r.logf("cleared the dirty flag of migration %d", st.Tracker)
			}
			if version != -1 {
				r.logf("recorded %s as applied", m.Stem())
			}
			return setTracker(ctx, tx, 0, false)
		})
	})
}

// Report is the migration state of a database against a directory.
type Report struct {
	Version int64 // the highest applied version; while dirty, the failed one
	Dirty   bool
	Applied int         // applied migrations, counting those up the version an earlier tool reached
	Pending []Migration // not applied yet, lowest first
	Unknown []int64
}

// Inspect reads the state without changing anything or taking the lock.
// Its error is either a read failure or one of the refusals (IsRefusal).
func Inspect(ctx context.Context, q queryer, migs []Migration) (Report, error) {
	st, err := readState(ctx, q)
	if err != nil {
		return Report{}, err
	}
	rep := Report{Dirty: st.Dirty}
	if st.Dirty || st.earlierTool() {
		rep.Version = st.Tracker
	}
	p, err := resolve(st, migs)
	if err != nil {
		return rep, err
	}
	rep.Version = max(rep.Version, p.Highest)
	rep.Applied = len(st.Applied) + len(p.Record)
	rep.Pending, rep.Unknown = p.Pending, p.Unknown
	return rep, nil
}

// Versions lists migration versions for messages ("a, b, c and 4 more").
func Versions(migs []Migration, limit int) string {
	names := make([]string, 0, min(len(migs), limit))
	for i, m := range migs {
		if i == limit {
			break
		}
		names = append(names, m.Stem())
	}
	s := strings.Join(names, ", ")
	if len(migs) > limit {
		s += fmt.Sprintf(" and %d more", len(migs)-limit)
	}
	return s
}

// Tracked reports whether the database has the schema_migrations table, i.e.
// whether any migration run has touched it.
func Tracked(ctx context.Context, q queryer) (bool, error) {
	return tableExists(ctx, q, trackerTable)
}

// AppliedVersion is the migration state the console and the metrics show:
// the highest applied version (while dirty, the version that failed; on a
// database the earlier tool migrated, its version) and the dirty flag.
// known is false when no migration run has touched the database.
func AppliedVersion(ctx context.Context, q queryer) (version int64, dirty, known bool, err error) {
	st, err := readState(ctx, q)
	if err != nil {
		return 0, false, false, err
	}
	if st.Dirty || st.earlierTool() {
		return st.Tracker, st.Dirty, true, nil
	}
	for v := range st.Applied {
		version = max(version, v)
	}
	return version, false, len(st.Applied) > 0, nil
}
