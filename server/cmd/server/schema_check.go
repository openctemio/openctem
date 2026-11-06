package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"

	"github.com/openctemio/openctem/api/internal/migrate"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// migrationUpFileRe matches a migration up file: VERSION_name.up.sql.
var migrationUpFileRe = regexp.MustCompile(`^(\d+)_.*\.up\.sql$`)

// migrationsDirPath returns the directory holding the .up.sql migrations,
// overridable via MIGRATIONS_DIR (the image ships them at ./migrations).
func migrationsDirPath() string {
	if d := os.Getenv("MIGRATIONS_DIR"); d != "" {
		return d
	}
	return "migrations"
}

// verifySchemaUpToDate fails fast when the DB schema is behind the migrations
// shipped with this binary.
//
// WHY: the server does not auto-migrate — migrations are applied out of band
// (scripts/migrate.sh / make migrate-up). When a deploy ships new code whose
// queries reference columns from an unapplied migration, EVERY request that
// touches those columns 500s (e.g. all auth returning "column federated_issuer
// does not exist"). That is a silent, total outage. This check converts it into
// an obvious refuse-to-start with an actionable message.
//
// Best-effort + fail-open on ambiguity: if the migration state can't be read
// (fresh DB, a different tracker format, unreadable dir) it logs and allows
// startup rather than false-blocking. A permission error is not ambiguity
// (the role is misconfigured) and refuses. Set SKIP_SCHEMA_CHECK=true to bypass.
func verifySchemaUpToDate(ctx context.Context, db *sql.DB, migrationsDir string, log *logger.Logger) error {
	if os.Getenv("SKIP_SCHEMA_CHECK") == "true" {
		log.Warn("schema up-to-date check skipped (SKIP_SCHEMA_CHECK=true)")
		return nil
	}

	migs, err := migrate.Load(migrationsDir)
	if err != nil || len(migs) == 0 {
		log.Warn("could not read the shipped migrations; skipping schema check",
			"dir", migrationsDir, "error", err)
		return nil
	}
	tracked, err := migrate.Tracked(ctx, db)
	if migrate.IsPermissionDenied(err) {
		return unreadableState(err)
	}
	if err != nil || !tracked {
		// No tracker at all: a different tracker format; don't hard-block boot.
		log.Warn("could not read schema_migrations; skipping schema check", "error", err)
		return nil
	}
	rels, err := migrate.LoadReleases(migrationsDir)
	if err != nil {
		log.Warn("could not read the released migrations list; a database the earlier tool migrated reads as undecided",
			"dir", migrationsDir, "error", err)
	}
	rep, err := migrate.Inspect(ctx, db, migs, migrate.Takeover{Releases: rels})
	return schemaProblem(rep, err, log)
}

// schemaProblem is the decision of verifySchemaUpToDate on the migration
// state: every shipped migration must be applied, whatever its version (a
// migration merged after a higher one counts as much as the newest one).
// A database a newer release migrated is fine (a rollback or a rolling
// deploy runs this binary on the newer schema) as long as it has every
// migration this binary ships. A role that may not read the migration state
// is a misconfiguration and refuses too; any other read failure (no tracker
// in a format this binary knows) is logged and startup goes on.
func schemaProblem(rep migrate.Report, err error, log *logger.Logger) error {
	var newer migrate.ErrNewerDatabase
	newerDB := errors.As(err, &newer)
	for _, x := range rep.Renamed {
		log.Warn("applied migration recorded under another name than the shipped file",
			"version", x.Version, "applied_name", x.Applied, "shipped_name", x.Shipped)
	}
	switch {
	case len(rep.Pending) > 0 && (err == nil || newerDB):
		return fmt.Errorf("database schema is behind: %d migrations shipped with this binary are not applied (%s); "+
			"run openctem-migrate up (make migrate-up) before starting, or set SKIP_SCHEMA_CHECK=true to override",
			len(rep.Pending), migrate.Versions(rep.Pending, 5))
	case newerDB:
		log.Info("database schema is ahead of this binary", "applied_version", newer.Applied, "latest_migration", newer.Shipped)
		return nil
	case err != nil && migrate.IsRefusal(err):
		return fmt.Errorf("database schema: %w", err)
	case migrate.IsPermissionDenied(err):
		return unreadableState(err)
	case err != nil:
		log.Warn("could not read the migration state; skipping schema check", "error", err)
		return nil
	}
	log.Info("database schema up to date", "applied_version", rep.Version, "applied_migrations", rep.Applied)
	return nil
}

// unreadableState is the refusal when the API's role may not read the
// migration tables.
func unreadableState(err error) error {
	return fmt.Errorf("database schema: the API's database role may not read the migration state: %w; "+
		"grant it SELECT on schema_migrations and schema_migrations_applied (re-run the database roles script), "+
		"or set SKIP_SCHEMA_CHECK=true to override", err)
}

// latestMigrationVersion returns the highest version in the dir's *.up.sql files.
func latestMigrationVersion(dir string) (int64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	var maxV int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := migrationUpFileRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		v, convErr := strconv.ParseInt(m[1], 10, 64)
		if convErr != nil {
			continue
		}
		if v > maxV {
			maxV = v
		}
	}
	return maxV, nil
}

// shippedSchemaVersion is the newest migration this binary ships, for the
// console overview (0 when the migrations directory cannot be read: the
// console then shows the applied version without a comparison).
func shippedSchemaVersion(log *logger.Logger) int64 {
	v, err := latestMigrationVersion(migrationsDirPath())
	if err != nil {
		log.Warn("console overview: shipped schema version unknown", "error", err)
		return 0
	}
	return v
}
