// Package migrate applies the SQL migrations in api/migrations to PostgreSQL
// and records every version it applied (docs/rfcs/RFC-130-migration-applied-set.md).
//
// A migration is a pair of files VERSION_name.up.sql / VERSION_name.down.sql.
// Versions only have to be unique: `up` applies every shipped migration the
// database has not applied yet, lowest version first, whatever the highest
// applied version is. So a migration merged after a higher-numbered one is
// applied on the next run instead of being skipped.
//
// Two tables hold the state, in the connection's current schema:
//
//   - schema_migrations_applied (version, name, applied_at): one row per
//     applied migration. The truth.
//   - schema_migrations (version, dirty): the earlier tool's tracker, kept as
//     a fence and the dirty flag. One row: (Fence, false) while clean, or
//     (version, true) while a migration failed midway. An older migrations
//     image refuses both, so it can never again skip a migration here.
//
// A database the earlier tool migrated has only schema_migrations, at its
// highest version V. On the first run ("takeover") every legacy-numbered
// file up to V is recorded as applied: that tool applied every version above
// the current one, and the legacy numbers only grew. A timestamp version up
// to V is undecidable (it skips one merged after a higher one) and is
// refused for an operator to settle with `force`.
package migrate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Migration is one versioned migration of a directory.
type Migration struct {
	Version  int64
	Name     string
	UpPath   string
	DownPath string // empty when the migration has no down file
}

// Stem is the file name without the .up.sql / .down.sql suffix.
func (m Migration) Stem() string { return filepath.Base(strings.TrimSuffix(m.UpPath, ".up.sql")) }

// Baseline reports whether m is the migration baseline: one file that
// replaces the chain up to its version (docs/rfcs/RFC-053-migration-baseline.md).
func (m Migration) Baseline() bool { return m.Name == "baseline" }

var fileRe = regexp.MustCompile(`^([0-9]+)_(.+)\.(up|down)\.sql$`)

// Load reads the migrations of dir, lowest version first. Files that are not
// migrations (sub-directories, READMEs) are ignored. It fails on two
// migrations with one version, a down file without its up file, and a
// baseline that is not the lowest version.
func Load(dir string) ([]Migration, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	byVersion := map[int64]*Migration{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := fileRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		v, convErr := strconv.ParseInt(m[1], 10, 64)
		if convErr != nil || v <= 0 || v == Fence {
			return nil, fmt.Errorf("migration %s: version must be a positive 64-bit number below %d", e.Name(), Fence)
		}
		cur := byVersion[v]
		if cur == nil {
			cur = &Migration{Version: v, Name: m[2]}
			byVersion[v] = cur
		}
		if cur.Name != m[2] {
			return nil, fmt.Errorf("migration version %d is used twice (%s and %s): versions must be unique", v, cur.Name, m[2])
		}
		path := filepath.Join(dir, e.Name())
		if m[3] == "up" {
			cur.UpPath = path
		} else {
			cur.DownPath = path
		}
	}
	out := make([]Migration, 0, len(byVersion))
	for _, m := range byVersion {
		if m.UpPath == "" {
			return nil, fmt.Errorf("migration %d_%s has a down file but no up file", m.Version, m.Name)
		}
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	for i, m := range out {
		if m.Baseline() && i != 0 {
			return nil, fmt.Errorf("migration baseline %s is not the lowest version", m.Stem())
		}
	}
	return out, nil
}

// ErrDirty: a migration failed midway; an operator has to look at the
// database and run `force` before anything else runs.
type ErrDirty struct{ Version int64 }

func (e ErrDirty) Error() string {
	return fmt.Sprintf("migration %d failed midway and the database is marked dirty: check what it changed, "+
		"then run `openctem-migrate force %d` if it is complete, or undo its partial changes and run "+
		"`openctem-migrate force -1` to retry it; nothing was changed", e.Version, e.Version)
}

// ErrOlderThanBaseline: the database predates the migration baseline, whose
// files replaced the migrations it still needs.
type ErrOlderThanBaseline struct{ Version, Baseline int64 }

func (e ErrOlderThanBaseline) Error() string {
	return fmt.Sprintf(`this database is at migration %d, older than the migration baseline %d.
This release creates the schema from one baseline file and cannot upgrade a
database older than it; nothing was changed. To upgrade:
  1. back up the database;
  2. deploy the last release before the baseline (git tag pre-baseline-%06d,
     which still ships every migration up to %d) and run its migrations;
  3. then deploy this release.
See docs/development/migrations.md, "Migration baseline"`, e.Version, e.Baseline, e.Baseline, e.Baseline)
}

// ErrNewerDatabase: the database has applied a migration above every one
// this release ships, so a newer release migrated it.
type ErrNewerDatabase struct{ Applied, Shipped int64 }

func (e ErrNewerDatabase) Error() string {
	return fmt.Sprintf("this database has migration %d applied, newer than any migration this release ships "+
		"(up to %d): a newer release migrated it; nothing was changed", e.Applied, e.Shipped)
}

// ErrTrackerMismatch: after this runner took the database over, another
// migration tool wrote schema_migrations (an older migrations image after
// `migrate force`, or a hand edit).
type ErrTrackerMismatch struct{ Tracker int64 }

func (e ErrTrackerMismatch) Error() string {
	return fmt.Sprintf("schema_migrations was set to %d by another migration tool after openctem-migrate took this "+
		"database over: check which migrations that tool applied or rolled back, record each applied one with "+
		"`openctem-migrate force VERSION` (force -1 if none), then run up; nothing was changed", e.Tracker)
}

// ErrUndecidedTakeover: the earlier tool migrated this database past
// timestamp versions, and it skips a version merged after a higher one
// without a trace, so which of them it applied cannot be known.
type ErrUndecidedTakeover struct {
	Tracker  int64
	Versions []int64
}

func (e ErrUndecidedTakeover) Error() string {
	return fmt.Sprintf("the earlier migration tool migrated this database to %d, past %d timestamp-versioned "+
		"migrations it may have skipped (%v): check each in the schema and record the applied ones with "+
		"`openctem-migrate force VERSION`; up then applies the rest. Nothing was changed",
		e.Tracker, len(e.Versions), e.Versions)
}

// IsRefusal reports whether err is one of the refusals above (the database
// was left unchanged), as opposed to a failure while applying.
func IsRefusal(err error) bool {
	var d ErrDirty
	var b ErrOlderThanBaseline
	var n ErrNewerDatabase
	var t ErrTrackerMismatch
	var u ErrUndecidedTakeover
	return errors.As(err, &d) || errors.As(err, &b) || errors.As(err, &n) || errors.As(err, &t) || errors.As(err, &u)
}
