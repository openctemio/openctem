// Package migrate applies the SQL migrations in api/migrations to PostgreSQL
// and records every version it applied (docs/rfcs/RFC-130-migration-applied-set.md).
//
// A migration is a pair of files VERSION_name.up.sql / VERSION_name.down.sql.
// Versions only have to be unique: `up` applies every shipped migration the
// database has not applied yet, lowest version first, whatever the highest
// applied version is. So a migration merged after a higher-numbered one is
// applied on the next run instead of being skipped.
//
// Two tables hold the state, in the connection's current schema when a run
// takes its lock (every statement of the run names that schema, so a
// migration that changes search_path cannot redirect the records):
//
//   - schema_migrations_applied (version, name, applied_at): one row per
//     applied migration. The truth.
//   - schema_migrations (version, dirty): the earlier tool's tracker, kept as
//     a fence and the dirty flag. One row: (Fence, false) while clean, or
//     (version, true) while a migration failed midway. An older migrations
//     image refuses both, so it can never again skip a migration here.
//
// A database the earlier tool migrated has only schema_migrations, at its
// highest version V. On the first run ("takeover") the files of the release
// whose highest version is V (released.json) are recorded as applied; every
// other file, one merged below V after that release was cut included, stays
// pending and runs. A database no release matches (a development build, or
// one left dirty) is refused until an operator lists what is applied
// (-assume-applied).
//
// Only the tables' owner may write them: each run revokes INSERT, UPDATE,
// DELETE and TRUNCATE on both from every other role (PUBLIC included), so a
// role that inherited write access through default privileges (an install
// whose roles script ran before these tables existed) cannot make a later
// run skip or repeat a migration.
package migrate

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/lib/pq"
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
// database and run `force` before anything else runs. EarlierTool: the
// earlier tool left it dirty, so which migrations below the failed one it
// applied is unknown and force needs the operator's list (-assume-applied).
type ErrDirty struct {
	Version     int64
	EarlierTool bool
}

func (e ErrDirty) Error() string {
	if e.EarlierTool {
		return fmt.Sprintf("migration %d failed midway under the earlier migration tool (golang-migrate) and the "+
			"database is marked dirty; that tool records only its highest version, so which migrations below %d "+
			"it applied cannot be known. Check the schema, list every applied version (one per line) in a file, "+
			"and run `openctem-migrate -assume-applied FILE force -1` (add %d to the list if it is complete; "+
			"otherwise undo its partial changes so up runs it again). Nothing was changed",
			e.Version, e.Version, e.Version)
	}
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

// ErrUndecidedTakeover: the earlier tool migrated this database and which
// migrations it applied cannot be known: its version is not the highest of
// exactly one release in released.json (a development build, or releases
// that end at one version with different files), or it left the database
// dirty. It records only its highest version and skips a migration merged
// below it, so recording "everything up to it" could mark a migration
// applied that never ran.
type ErrUndecidedTakeover struct {
	Tracker   int64
	Dirty     bool
	Ambiguous []string // release tags that end at Tracker with different files
}

func (e ErrUndecidedTakeover) Error() string {
	why := fmt.Sprintf("version %d is not the last migration of any release that shipped that tool (%s)", e.Tracker, ReleasedFile)
	switch {
	case e.Dirty:
		why = fmt.Sprintf("it left the database dirty at %d", e.Tracker)
	case len(e.Ambiguous) > 0:
		why = fmt.Sprintf("releases with different migrations end at version %d (%s)", e.Tracker, strings.Join(e.Ambiguous, ", "))
	}
	return fmt.Sprintf("the earlier migration tool (golang-migrate) migrated this database, and which migrations it "+
		"applied cannot be known: %s. That tool records only its highest version and skips a migration merged "+
		"below it. Check the schema, list every applied version (one per line) in a file, and pass it with "+
		"`openctem-migrate -assume-applied FILE up` (or force); every other shipped migration then runs. "+
		"Nothing was changed", why)
}

// ReleasedFile is the file in the migrations directory that lists the
// migration versions of every release that shipped the earlier tool
// (generated by scripts/released-migrations.sh).
const ReleasedFile = "released.json"

// LoadReleases reads dir/released.json. A missing file reads as no
// releases: a database the earlier tool migrated is then taken over only
// with an operator's list.
func LoadReleases(dir string) ([]Release, error) {
	body, err := os.ReadFile(filepath.Join(dir, ReleasedFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", ReleasedFile, err)
	}
	var doc struct {
		Releases []Release `json:"releases"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", ReleasedFile, err)
	}
	return doc.Releases, nil
}

// ParseAssumeApplied reads an operator's list of applied versions (one per
// line; blank lines and # comments ignored; a file name like
// 003420_x.up.sql counts as its version). Every version must be shipped in
// migs: a typo must not silently leave a migration to run again.
func ParseAssumeApplied(r io.Reader, migs []Migration) (map[int64]bool, error) {
	shipped := make(map[int64]bool, len(migs))
	for _, m := range migs {
		shipped[m.Version] = true
	}
	out := map[int64]bool{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		digits := line
		if i := strings.IndexByte(line, '_'); i > 0 {
			digits = line[:i]
		}
		v, err := strconv.ParseInt(digits, 10, 64)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("assumed-applied list, line %d: %q is not a migration version", n, line)
		}
		if !shipped[v] {
			return nil, fmt.Errorf("assumed-applied list, line %d: no migration with version %d in this directory", n, v)
		}
		out[v] = true
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read the assumed-applied list: %w", err)
	}
	return out, nil
}

// IsPermissionDenied reports whether err is PostgreSQL's
// insufficient_privilege (42501): the connecting role may not read or write
// what it needs, which is a misconfiguration, never a reason to skip a check.
func IsPermissionDenied(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "42501"
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
