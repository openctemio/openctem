package postgres

// Statement timeouts of statements that can legitimately outlast the app
// role's limit (deploy/postgres/least-privilege-roles.sql, default 60s): bulk
// feed upserts, retention deletes, backfills, full dashboard runs, merges.
// Each such statement raises the limit for its own transaction with SET LOCAL,
// to one of the bounded values below, so a runaway statement is still stopped
// and the limit returns to the role's value at commit. The inventory is in
// docs/deployment/database-roles.md ("Long statements").

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

const (
	// timeoutBatch bounds one batched write of a background job (retention
	// delete batch, backfill batch, bulk upsert chunk).
	timeoutBatch = 5 * time.Minute
	// timeoutHeavy bounds one set-based statement over a whole table or
	// tenant (feed sync, rollups, dashboard run step, merges, rebuilds).
	timeoutHeavy = 15 * time.Minute
	// maxStatementTimeout is the ceiling no caller may exceed.
	maxStatementTimeout = 30 * time.Minute
)

// setLocalStatementTimeout sets statement_timeout for the rest of tx. The
// value is formatted from a duration, never from caller text.
func setLocalStatementTimeout(ctx context.Context, tx *sql.Tx, d time.Duration) error {
	if d <= 0 || d > maxStatementTimeout {
		return fmt.Errorf("statement timeout %s is outside (0, %s]", d, maxStatementTimeout)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("SET LOCAL statement_timeout = %d", d.Milliseconds())); err != nil {
		return fmt.Errorf("set statement timeout: %w", err)
	}
	return nil
}

// withStatementTimeout runs fn in one transaction whose statements may take up
// to d each. It commits when fn returns nil.
func withStatementTimeout(ctx context.Context, db *sql.DB, d time.Duration, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := setLocalStatementTimeout(ctx, tx, d); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// execWithTimeout runs one statement with a limit of d.
func execWithTimeout(ctx context.Context, db *sql.DB, d time.Duration, query string, args ...any) (sql.Result, error) {
	var res sql.Result
	err := withStatementTimeout(ctx, db, d, func(tx *sql.Tx) (err error) {
		res, err = tx.ExecContext(ctx, query, args...)
		return err
	})
	return res, err
}

// queryRowWithTimeout runs one single-row query with a limit of d and scans
// it into dest.
func queryRowWithTimeout(ctx context.Context, db *sql.DB, d time.Duration, query string, args []any, dest ...any) error {
	return withStatementTimeout(ctx, db, d, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, args...).Scan(dest...)
	})
}
