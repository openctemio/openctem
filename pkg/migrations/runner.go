package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Runner executes database migrations with edition awareness.
type Runner struct {
	db            *sql.DB
	migrationsDir string
	edition       Edition
}

// NewRunner creates a new migration runner.
func NewRunner(db *sql.DB, migrationsDir string, edition Edition) *Runner {
	return &Runner{
		db:            db,
		migrationsDir: migrationsDir,
		edition:       edition,
	}
}

// MigrationRecord represents a migration in the schema_migrations table.
type MigrationRecord struct {
	Version   string
	AppliedAt time.Time
	Edition   string
}

// EnsureMigrationTable creates the schema_migrations table if it doesn't exist.
func (r *Runner) EnsureMigrationTable(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(14) PRIMARY KEY,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			edition VARCHAR(20) DEFAULT 'core'
		);

		-- Add edition column if it doesn't exist (for upgrades)
		DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_name = 'schema_migrations' AND column_name = 'edition'
			) THEN
				ALTER TABLE schema_migrations ADD COLUMN edition VARCHAR(20) DEFAULT 'core';
			END IF;
		END $$;
	`
	_, err := r.db.ExecContext(ctx, query)
	return err
}

// GetAppliedMigrations returns all applied migration versions.
func (r *Runner) GetAppliedMigrations(ctx context.Context) ([]MigrationRecord, error) {
	query := `SELECT version, applied_at, COALESCE(edition, 'core') FROM schema_migrations ORDER BY version`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []MigrationRecord
	for rows.Next() {
		var rec MigrationRecord
		if err := rows.Scan(&rec.Version, &rec.AppliedAt, &rec.Edition); err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}

// GetPendingMigrations returns migrations that need to be applied.
func (r *Runner) GetPendingMigrations(ctx context.Context) ([]string, error) {
	// Get available migrations from filesystem
	available, err := r.scanMigrationFiles()
	if err != nil {
		return nil, fmt.Errorf("failed to scan migrations: %w", err)
	}

	// Filter by edition
	available = FilterMigrations(available, r.edition)

	// Get applied migrations
	applied, err := r.GetAppliedMigrations(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get applied migrations: %w", err)
	}

	appliedSet := make(map[string]bool)
	for _, rec := range applied {
		appliedSet[rec.Version] = true
	}

	// Find pending
	var pending []string
	for _, v := range available {
		if !appliedSet[v] {
			pending = append(pending, v)
		}
	}

	sort.Strings(pending)
	return pending, nil
}

// Up runs all pending migrations.
func (r *Runner) Up(ctx context.Context) error {
	if err := r.EnsureMigrationTable(ctx); err != nil {
		return fmt.Errorf("failed to ensure migration table: %w", err)
	}

	pending, err := r.GetPendingMigrations(ctx)
	if err != nil {
		return err
	}

	if len(pending) == 0 {
		fmt.Println("No pending migrations")
		return nil
	}

	fmt.Printf("Running %d migrations for edition '%s'...\n", len(pending), r.edition)

	for _, version := range pending {
		if err := r.runMigration(ctx, version, "up"); err != nil {
			return fmt.Errorf("migration %s failed: %w", version, err)
		}
		fmt.Printf("  Applied: %s\n", version)
	}

	return nil
}

// Down rolls back the last migration.
func (r *Runner) Down(ctx context.Context) error {
	applied, err := r.GetAppliedMigrations(ctx)
	if err != nil {
		return err
	}

	if len(applied) == 0 {
		fmt.Println("No migrations to rollback")
		return nil
	}

	// Get the last migration
	last := applied[len(applied)-1]

	// Check if this migration is for our edition
	if !ShouldRunMigration(last.Version, r.edition) {
		return fmt.Errorf("migration %s is not for edition %s", last.Version, r.edition)
	}

	if err := r.runMigration(ctx, last.Version, "down"); err != nil {
		return fmt.Errorf("rollback %s failed: %w", last.Version, err)
	}

	// Remove from schema_migrations
	_, err = r.db.ExecContext(ctx, "DELETE FROM schema_migrations WHERE version = $1", last.Version)
	if err != nil {
		return fmt.Errorf("failed to remove migration record: %w", err)
	}

	fmt.Printf("Rolled back: %s\n", last.Version)
	return nil
}

// runMigration executes a single migration.
func (r *Runner) runMigration(ctx context.Context, version, direction string) error {
	// Find the migration file
	pattern := filepath.Join(r.migrationsDir, fmt.Sprintf("%s_*.%s.sql", version, direction))
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}
	if len(matches) == 0 {
		return fmt.Errorf("migration file not found: %s", pattern)
	}

	content, err := os.ReadFile(matches[0])
	if err != nil {
		return err
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Execute migration
	if _, err := tx.ExecContext(ctx, string(content)); err != nil {
		return err
	}

	// Record migration (only for 'up')
	if direction == "up" {
		edition := GetMigrationEdition(version)
		_, err = tx.ExecContext(ctx,
			"INSERT INTO schema_migrations (version, edition) VALUES ($1, $2)",
			version, string(edition))
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// scanMigrationFiles scans the migrations directory for available versions.
func (r *Runner) scanMigrationFiles() ([]string, error) {
	versions := make(map[string]bool)

	err := filepath.WalkDir(r.migrationsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".up.sql") {
			return nil
		}

		filename := filepath.Base(path)
		parts := strings.SplitN(filename, "_", 2)
		if len(parts) >= 1 {
			versions[parts[0]] = true
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	var result []string
	for v := range versions {
		result = append(result, v)
	}
	sort.Strings(result)
	return result, nil
}

// Status prints the migration status.
func (r *Runner) Status(ctx context.Context) error {
	if err := r.EnsureMigrationTable(ctx); err != nil {
		return err
	}

	applied, err := r.GetAppliedMigrations(ctx)
	if err != nil {
		return err
	}

	available, err := r.scanMigrationFiles()
	if err != nil {
		return err
	}

	appliedSet := make(map[string]MigrationRecord)
	for _, rec := range applied {
		appliedSet[rec.Version] = rec
	}

	fmt.Printf("Migration Status (Edition: %s)\n", r.edition)
	fmt.Println("=====================================")

	for _, v := range available {
		edition := GetMigrationEdition(v)
		status := "pending"
		if rec, ok := appliedSet[v]; ok {
			status = fmt.Sprintf("applied (%s)", rec.AppliedAt.Format("2006-01-02"))
		}

		// Mark if migration is for this edition
		editionMark := ""
		if !ShouldRunMigration(v, r.edition) {
			editionMark = " [skip]"
		}

		fmt.Printf("  %s (%s): %s%s\n", v, edition, status, editionMark)
	}

	return nil
}
