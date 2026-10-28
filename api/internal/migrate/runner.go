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

	"github.com/lib/pq"
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
	Takeover    Takeover             // how a database the earlier tool migrated is taken over
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

// tables names the two tracking tables, qualified with the schema a run
// found current when it took the lock. A migration file may change
// search_path for the rest of the session; the records still go where the
// lock (and the state the run read) belong.
type tables struct {
	schema  string // unquoted
	tracker string // quoted and qualified
	applied string

	// Statements on schema_migrations_applied (identifiers quoted above).
	recordSQL   string // insert, keeping a row already there
	insertSQL   string
	deleteSQL   string
	selectSQL   string // version, name
	recentSQL   string // the $1 most recently applied versions
	trackerRead string
}

func tablesIn(schema string) tables {
	q := pq.QuoteIdentifier(schema)
	t := tables{
		schema:  schema,
		tracker: q + "." + pq.QuoteIdentifier(trackerTable),
		applied: q + "." + pq.QuoteIdentifier(appliedTable),
	}
	t.recordSQL = "INSERT INTO " + t.applied + " (version, name) VALUES ($1, $2) ON CONFLICT (version) DO NOTHING"
	t.insertSQL = "INSERT INTO " + t.applied + " (version, name) VALUES ($1, $2)"
	t.deleteSQL = "DELETE FROM " + t.applied + " WHERE version = $1"
	t.selectSQL = "SELECT version, name FROM " + t.applied
	t.recentSQL = "SELECT version FROM " + t.applied + " ORDER BY applied_at DESC, version DESC LIMIT $1"
	t.trackerRead = "SELECT version, dirty FROM " + t.tracker + " ORDER BY version DESC LIMIT 1"
	return t
}

// currentTables names the tracking tables of the connection's current schema.
func currentTables(ctx context.Context, q queryer) (tables, error) {
	var schema sql.NullString
	if err := q.QueryRowContext(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		return tables{}, fmt.Errorf("read the current schema: %w", err)
	}
	if !schema.Valid {
		return tables{}, errors.New("the connection has no current schema (check search_path)")
	}
	return tablesIn(schema.String), nil
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
func (r *Runner) withLock(ctx context.Context, fn func(*sql.Conn, tables) error) error {
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
		// Not the run's context: the lock must go even when it was canceled.
		uctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(uctx, `SELECT pg_advisory_unlock($1)`, key)
	}()
	return fn(conn, tablesIn(schema.String))
}

// ensureTables creates the two tracking tables when they are missing, then
// makes sure only their owner can write them. It checks first, so a role
// without CREATE on the schema works on a database that has them (the roles
// script creates both ahead of the first run).
func (r *Runner) ensureTables(ctx context.Context, conn *sql.Conn, t tables) error {
	ddl := map[string]string{
		trackerTable: `CREATE TABLE IF NOT EXISTS ` + t.tracker + ` (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL)`,
		appliedTable: `CREATE TABLE IF NOT EXISTS ` + t.applied + ` (
			version bigint NOT NULL PRIMARY KEY,
			name text NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
	}
	for _, name := range []string{trackerTable, appliedTable} {
		exists, err := tableExists(ctx, conn, t.schema, name)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := conn.ExecContext(ctx, ddl[name]); err != nil {
			return fmt.Errorf("create %s: %w", name, err)
		}
	}
	return r.ownerOnlyWrites(ctx, conn, t)
}

// ownerOnlyWrites revokes INSERT, UPDATE, DELETE and TRUNCATE on the
// tracking tables from every role but their owner (PUBLIC included). The
// roles script grants the app role SELECT only, but an install that never
// re-ran it after this runner created the tables gave the app full DML
// through the migrator's default privileges; a role that can write them can
// make the next run skip a migration or run one again. When the run's role
// cannot revoke (it does not own the tables), it says so.
func (r *Runner) ownerOnlyWrites(ctx context.Context, conn *sql.Conn, t tables) error {
	for _, table := range []string{t.tracker, t.applied} {
		found, err := writeGrantees(ctx, conn, table)
		if err != nil {
			return err
		}
		for _, g := range found {
			who := pq.QuoteIdentifier(g.name)
			if g.isPublic {
				who, g.name = "PUBLIC", "PUBLIC"
			}
			if !g.canFix {
				r.logf("warning: role %s may write %s, and this run's role cannot revoke it: re-run the database roles script", g.name, table)
				continue
			}
			if _, err := conn.ExecContext(ctx, "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON "+table+" FROM "+who); err != nil {
				return fmt.Errorf("revoke writes on %s from %s: %w", table, g.name, err)
			}
			r.logf("revoked write access to %s from %s (only the migration role may write it)", table, g.name)
		}
	}
	return nil
}

// grantee is a role (or PUBLIC) holding a write privilege on a table it
// does not own; canFix: the current role may revoke it (owns the table).
type grantee struct {
	name     string
	isPublic bool
	canFix   bool
}

func writeGrantees(ctx context.Context, conn *sql.Conn, table string) ([]grantee, error) {
	rows, err := conn.QueryContext(ctx, `
		SELECT DISTINCT a.grantee = 0, coalesce(g.rolname, ''),
		       pg_has_role(current_user, c.relowner, 'USAGE')
		FROM pg_class c
		CROSS JOIN LATERAL aclexplode(c.relacl) a
		LEFT JOIN pg_roles g ON g.oid = a.grantee
		WHERE c.oid = $1::regclass AND a.grantee <> c.relowner
		  AND a.privilege_type IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')`, table)
	if err != nil {
		return nil, fmt.Errorf("read the privileges on %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	var found []grantee
	for rows.Next() {
		var g grantee
		if err := rows.Scan(&g.isPublic, &g.name, &g.canFix); err != nil {
			return nil, err
		}
		found = append(found, g)
	}
	return found, rows.Err()
}

func tableExists(ctx context.Context, q queryer, schema, table string) (bool, error) {
	var exists bool
	err := q.QueryRowContext(ctx,
		`SELECT to_regclass(quote_ident($1) || '.' || quote_ident($2)) IS NOT NULL`, schema, table).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("look up %s: %w", table, err)
	}
	return exists, nil
}

// readState reads both tables; a missing table reads as empty.
func readState(ctx context.Context, q queryer, t tables) (dbState, error) {
	st := dbState{Applied: map[int64]bool{}, Names: map[int64]string{}}
	if ok, err := tableExists(ctx, q, t.schema, trackerTable); err != nil {
		return st, err
	} else if ok {
		err := q.QueryRowContext(ctx, t.trackerRead).
			Scan(&st.Tracker, &st.Dirty)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return st, fmt.Errorf("read schema_migrations: %w", err)
		}
		// The earlier tool writes -1 for "nothing applied" after a failed
		// first down migration.
		st.Tracker = max(st.Tracker, 0)
	}
	ok, err := tableExists(ctx, q, t.schema, appliedTable)
	if err != nil || !ok {
		return st, err
	}
	rows, err := q.QueryContext(ctx, t.selectSQL)
	if err != nil {
		return st, fmt.Errorf("read schema_migrations_applied: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var v int64
		var name string
		if err := rows.Scan(&v, &name); err != nil {
			return st, err
		}
		st.Applied[v] = true
		st.Names[v] = name
	}
	return st, rows.Err()
}

// setTracker writes the single schema_migrations row: (Fence, false) while
// clean, (version, true) while a migration runs.
func setTracker(ctx context.Context, x execer, t tables, version int64, dirty bool) error {
	if !dirty {
		version = Fence
	}
	if _, err := x.ExecContext(ctx, `DELETE FROM `+t.tracker); err != nil {
		return fmt.Errorf("write schema_migrations: %w", err)
	}
	if _, err := x.ExecContext(ctx, `INSERT INTO `+t.tracker+` (version, dirty) VALUES ($1, $2)`, version, dirty); err != nil {
		return fmt.Errorf("write schema_migrations: %w", err)
	}
	return nil
}

// markDirty records, before a migration file runs, that it is running: a
// failure or a crash midway leaves the database dirty at that version.
func markDirty(ctx context.Context, conn *sql.Conn, t tables, version int64) error {
	return inTx(ctx, conn, func(tx *sql.Tx) error { return setTracker(ctx, tx, t, version, true) })
}

// record inserts applied rows (already recorded ones are kept).
func record(ctx context.Context, tx *sql.Tx, t tables, migs []Migration) error {
	for _, m := range migs {
		if _, err := tx.ExecContext(ctx, t.recordSQL, m.Version, m.Name); err != nil {
			return fmt.Errorf("record %s: %w", m.Stem(), err)
		}
	}
	return nil
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
func (r *Runner) prepare(ctx context.Context, conn *sql.Conn, t tables) (plan, error) {
	if err := r.ensureTables(ctx, conn, t); err != nil {
		return plan{}, err
	}
	st, err := readState(ctx, conn, t)
	if err != nil {
		return plan{}, err
	}
	p, err := resolve(st, r.Migrations, r.Takeover)
	if err != nil {
		return p, err
	}
	if r.Takeover.AssumeApplied != nil && !st.earlierTool() {
		r.logf("the assumed-applied list is ignored: this database is not the earlier migration tool's")
	}
	if len(p.Record) > 0 || st.Tracker != Fence {
		err := inTx(ctx, conn, func(tx *sql.Tx) error {
			if err := record(ctx, tx, t, p.Record); err != nil {
				return err
			}
			return setTracker(ctx, tx, t, 0, false)
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
	for _, x := range p.Renamed {
		r.logf("warning: migration %d was applied as %q, but this directory ships it as %q: a merged migration "+
			"must never be renamed or replaced (the applied one never runs again)", x.Version, x.Applied, x.Shipped)
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
	err := r.withLock(ctx, func(conn *sql.Conn, t tables) error {
		p, err := r.prepare(ctx, conn, t)
		res.Recorded, res.Unknown = p.Record, p.Unknown
		if err != nil {
			return err
		}
		highest := p.Highest
		for _, m := range p.Pending {
			if err := markDirty(ctx, conn, t, m.Version); err != nil {
				return err
			}
			start := time.Now()
			if err := runFile(ctx, conn, m.UpPath); err != nil {
				return fmt.Errorf("migration %s failed; the database is marked dirty at %d: %w", m.Stem(), m.Version, err)
			}
			highest = max(highest, m.Version)
			err := inTx(ctx, conn, func(tx *sql.Tx) error {
				if _, err := tx.ExecContext(ctx, t.insertSQL, m.Version, m.Name); err != nil {
					return fmt.Errorf("record %s: %w", m.Stem(), err)
				}
				return setTracker(ctx, tx, t, 0, false)
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
	err := r.withLock(ctx, func(conn *sql.Conn, t tables) error {
		if _, err := r.prepare(ctx, conn, t); err != nil {
			return err
		}
		versions, err := recentlyApplied(ctx, conn, t, n)
		if err != nil {
			return err
		}
		for _, v := range versions {
			m, ok := byVersion[v]
			if !ok || m.DownPath == "" {
				return fmt.Errorf("migration %d has no down file in this directory; nothing more was rolled back", v)
			}
			if err := markDirty(ctx, conn, t, v); err != nil {
				return err
			}
			if err := runFile(ctx, conn, m.DownPath); err != nil {
				return fmt.Errorf("down migration %s failed; the database is marked dirty at %d: %w", m.Stem(), v, err)
			}
			err := inTx(ctx, conn, func(tx *sql.Tx) error {
				if _, err := tx.ExecContext(ctx, t.deleteSQL, v); err != nil {
					return err
				}
				return setTracker(ctx, tx, t, 0, false)
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

// recentlyApplied lists the n most recently applied versions, newest first.
func recentlyApplied(ctx context.Context, q queryer, t tables, n int) ([]int64, error) {
	rows, err := q.QueryContext(ctx, t.recentSQL, n)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations_applied: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var versions []int64
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

// Force clears the dirty flag and records version as applied without
// running it; version -1 records nothing. After a failed migration: force
// its own version when it completed (or was finished by hand), or -1 after
// undoing its partial changes, so the next up runs it again. On a database
// the earlier tool migrated it first takes it over as up would (Takeover):
// with the matching release's files, or the operator's list. A dirty one has
// no matching release (that tool stopped midway), so there force refuses
// without the list: clearing the flag must not forget, or invent, which
// migrations below the failed one ran.
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
	return r.withLock(ctx, func(conn *sql.Conn, t tables) error {
		if err := r.ensureTables(ctx, conn, t); err != nil {
			return err
		}
		st, err := readState(ctx, conn, t)
		if err != nil {
			return err
		}
		var toRecord []Migration
		if len(st.Applied) == 0 && st.Tracker > 0 && st.Tracker != Fence {
			// The earlier tool's database.
			recorded, err := r.Takeover.takeover(st.Tracker, st.Dirty, r.Migrations)
			if err != nil {
				return err
			}
			toRecord = recorded
		}
		if version != -1 {
			toRecord = append(toRecord, m)
		}
		return inTx(ctx, conn, func(tx *sql.Tx) error {
			if err := record(ctx, tx, t, toRecord); err != nil {
				return err
			}
			if st.Dirty {
				r.logf("cleared the dirty flag of migration %d", st.Tracker)
			}
			if version != -1 {
				r.logf("recorded %s as applied", m.Stem())
			}
			return setTracker(ctx, tx, t, 0, false)
		})
	})
}

// Report is the migration state of a database against a directory.
type Report struct {
	Version int64 // the highest applied version; while dirty, the failed one
	Dirty   bool
	Applied int         // applied migrations, counting those a takeover of the earlier tool's database records
	Pending []Migration // not applied yet, lowest first
	Unknown []int64
	Renamed []Renamed
}

// Inspect reads the state without changing anything or taking the lock.
// Its error is either a read failure or one of the refusals (IsRefusal).
//
// With ErrNewerDatabase the report is still filled in: Pending lists what
// this directory ships that the newer release's database lacks.
func Inspect(ctx context.Context, q queryer, migs []Migration, tk Takeover) (Report, error) {
	t, err := currentTables(ctx, q)
	if err != nil {
		return Report{}, err
	}
	st, err := readState(ctx, q, t)
	if err != nil {
		return Report{}, err
	}
	rep := Report{Dirty: st.Dirty}
	if st.Dirty || st.earlierTool() {
		rep.Version = st.Tracker
	}
	p, err := resolve(st, migs, tk)
	var newer ErrNewerDatabase
	if err != nil && !errors.As(err, &newer) {
		return rep, err
	}
	rep.Version = max(rep.Version, p.Highest)
	rep.Applied = len(st.Applied) + len(p.Record)
	rep.Pending, rep.Unknown, rep.Renamed = p.Pending, p.Unknown, p.Renamed
	return rep, err
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
	t, err := currentTables(ctx, q)
	if err != nil {
		return false, err
	}
	return tableExists(ctx, q, t.schema, trackerTable)
}

// AppliedVersion is the migration state the console and the metrics show:
// the highest applied version (while dirty, the version that failed; on a
// database the earlier tool migrated, its version) and the dirty flag.
// known is false when no migration run has touched the database.
func AppliedVersion(ctx context.Context, q queryer) (version int64, dirty, known bool, err error) {
	t, err := currentTables(ctx, q)
	if err != nil {
		return 0, false, false, err
	}
	st, err := readState(ctx, q, t)
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
