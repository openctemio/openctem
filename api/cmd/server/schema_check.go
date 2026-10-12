package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// migrationUpFileRe matches a golang-migrate up file: NNNN_name.up.sql.
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
// startup rather than false-blocking. Set SKIP_SCHEMA_CHECK=true to bypass.
func verifySchemaUpToDate(ctx context.Context, db *sql.DB, migrationsDir string, log *logger.Logger) error {
	if os.Getenv("SKIP_SCHEMA_CHECK") == "true" {
		log.Warn("schema up-to-date check skipped (SKIP_SCHEMA_CHECK=true)")
		return nil
	}

	latest, err := latestMigrationVersion(migrationsDir)
	if err != nil || latest == 0 {
		log.Warn("could not determine latest migration version; skipping schema check",
			"dir", migrationsDir, "error", err)
		return nil
	}

	// golang-migrate tracks a single (version, dirty) row.
	var version int64
	var dirty bool
	row := db.QueryRowContext(ctx, `SELECT version, dirty FROM schema_migrations ORDER BY version DESC LIMIT 1`)
	switch scanErr := row.Scan(&version, &dirty); {
	case errors.Is(scanErr, sql.ErrNoRows):
		version = 0 // fresh DB, nothing applied yet
	case scanErr != nil:
		// table missing / a different tracker format — don't hard-block boot.
		log.Warn("could not read schema_migrations; skipping schema check", "error", scanErr)
		return nil
	}

	if err := schemaVersionProblem(version, dirty, latest, baselineMigrationVersion(migrationsDir)); err != nil {
		return err
	}

	log.Info("database schema up to date", "applied_version", version, "latest_migration", latest)
	return nil
}

// schemaVersionProblem is the decision of verifySchemaUpToDate for an applied
// (version, dirty) pair, the newest shipped migration and the migration
// baseline (0 when the directory has none).
//
// A database older than the baseline cannot be migrated by this release at all
// (golang-migrate refuses it: its version has no file any more), so that is
// said first and plainly, with the way out (docs/rfcs/RFC-053-migration-baseline.md).
func schemaVersionProblem(version int64, dirty bool, latest, baseline int64) error {
	if version > 0 && baseline > 0 && version < baseline {
		return fmt.Errorf("database is at migration %d, older than the migration baseline %d: this release "+
			"cannot upgrade it. Back it up, deploy the last release before the baseline (git tag "+
			"pre-baseline-%06d) and run its migrations, then deploy this release "+
			"(docs/development/migrations.md, \"Migration baseline\")", version, baseline, baseline)
	}
	if dirty {
		return fmt.Errorf("schema_migrations is DIRTY at version %d — a migration failed midway; "+
			"resolve it (force to a clean version) before starting", version)
	}
	if version < latest {
		return fmt.Errorf("database schema is behind: applied version %d, this binary ships migrations "+
			"up to %d — apply migrations (make migrate-up / scripts/migrate.sh up) before starting, "+
			"or set SKIP_SCHEMA_CHECK=true to override", version, latest)
	}
	return nil
}

// migrationBaselineFileRe matches the migration baseline: NNNN_baseline.up.sql.
var migrationBaselineFileRe = regexp.MustCompile(`^(\d+)_baseline\.up\.sql$`)

// baselineMigrationVersion returns the version of the dir's baseline file, or
// 0 when there is none (or the dir cannot be read).
func baselineMigrationVersion(dir string) int64 {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if m := migrationBaselineFileRe.FindStringSubmatch(e.Name()); m != nil && !e.IsDir() {
			if v, convErr := strconv.ParseInt(m[1], 10, 64); convErr == nil {
				return v
			}
		}
	}
	return 0
}

// latestMigrationVersion returns the highest NNNN in the dir's *.up.sql files.
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
