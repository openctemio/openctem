package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/aianalysis"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/config"
)

// DB wraps sql.DB with additional functionality.
type DB struct {
	*sql.DB
}

// New creates a new database connection.
func New(cfg *config.DatabaseConfig) (*DB, error) {
	db, err := sql.Open("postgres", cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DB{DB: db}, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.DB.Close()
}

// HealthCheck performs a health check on the database.
func (db *DB) HealthCheck(ctx context.Context) error {
	return db.PingContext(ctx)
}

// Ping implements the Pinger interface for health checks.
func (db *DB) Ping(ctx context.Context) error {
	return db.PingContext(ctx)
}

// Transaction executes a function within a database transaction.
func (db *DB) Transaction(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("failed to rollback transaction: %v (original error: %w)", rbErr, err)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// ExecContext runs a statement, refused in a read-only AI assistance context
// (aianalysis.WithAssist): assistance runs under the viewer and writes
// nothing (docs/architecture/ai-analysis.md).
func (db *DB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if err := aianalysis.RefuseAssist(ctx); err != nil {
		return nil, err
	}
	return db.DB.ExecContext(ctx, query, args...)
}

// BeginTx starts a transaction; in a read-only AI assistance context only a
// read-only transaction may start.
func (db *DB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	if opts == nil || !opts.ReadOnly {
		if err := aianalysis.RefuseAssist(ctx); err != nil {
			return nil, err
		}
	}
	return db.DB.BeginTx(ctx, opts)
}

// QueryContext runs a query; in a read-only AI assistance context a writing
// statement (INSERT, UPDATE, DELETE, MERGE, or a WITH that writes) is
// refused.
func (db *DB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if aianalysis.IsAssist(ctx) && writesData(query) {
		return nil, aianalysis.ErrAssistReadOnly
	}
	return db.DB.QueryContext(ctx, query, args...)
}

// QueryRowContext is QueryContext for one row. A refused write surfaces as
// the row's error.
func (db *DB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	if aianalysis.IsAssist(ctx) && writesData(query) {
		// A canceled context makes the row report an error without running
		// the statement.
		c, cancel := context.WithCancelCause(ctx)
		cancel(aianalysis.ErrAssistReadOnly)
		return db.DB.QueryRowContext(c, query, args...)
	}
	return db.DB.QueryRowContext(ctx, query, args...)
}

// writesData reports whether a statement writes: its first keyword, or any
// data-modifying keyword in a WITH statement.
func writesData(query string) bool {
	q := strings.ToUpper(strings.TrimSpace(query))
	for _, kw := range []string{"INSERT", "UPDATE", "DELETE", "MERGE", "TRUNCATE"} {
		if strings.HasPrefix(q, kw) {
			return true
		}
	}
	if strings.HasPrefix(q, "WITH") {
		for _, kw := range []string{"INSERT ", "UPDATE ", "DELETE ", "MERGE "} {
			if strings.Contains(q, kw) {
				return true
			}
		}
	}
	return false
}
