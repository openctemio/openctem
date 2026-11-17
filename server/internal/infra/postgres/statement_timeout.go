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
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
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

// Interactive reads (docs/architecture/list-query-contract.md, "Timeouts"):
// every list, count, stats, facet, group and export page a person waits for
// runs in beginRead, a READ ONLY transaction whose statements stop after a
// bound, so a broad filter answers 503 QUERY_TIMEOUT instead of holding a
// pool connection until the role's limit (60 s, or none on an install that
// did not apply deploy/postgres/least-privilege-roles.sql). A read that runs
// out of time is mapped by readTimeout: counted in
// openctem_db_read_timeouts_total{read} and logged once, by name, never
// with the statement or its values.

// interactiveReadTimeout bounds each statement of an interactive read.
const interactiveReadTimeout = 5 * time.Second

// Names of the interactive reads, the closed label set of readTimeouts.
const (
	readFindings       = "findings"
	readFindingGroups  = "finding_groups"
	readFindingExport  = "finding_export"
	readAssets         = "assets"
	readComponents     = "components"
	readScans          = "scans"
	readWebEndpoints   = "web_endpoints"
	readCertificates   = "certificates"
	readTechnologies   = "technologies"
	readExposureItems  = "exposure_items"
	readCVEExposures   = "cve_exposures"
	readAssetIPContext = "asset_ip_context"
)

// readTimeouts counts the interactive reads stopped by their statement
// timeout. A rising count names the read whose filters need an index or a
// precomputed figure.
var readTimeouts = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "openctem",
	Subsystem: "db",
	Name:      "read_timeouts_total",
	Help:      "Interactive reads (lists, counts, stats, facets, groups, export pages) stopped by their statement timeout, by read.",
}, []string{"read"})

// beginRead opens a READ ONLY transaction whose statements stop after d.
// The caller rolls it back or commits it.
func beginRead(ctx context.Context, db *sql.DB, d time.Duration) (*sql.Tx, error) {
	return beginReadTx(ctx, db, d, sql.LevelDefault)
}

// beginReadSnapshot is beginRead in one REPEATABLE READ snapshot (an export
// that reads several pages).
func beginReadSnapshot(ctx context.Context, db *sql.DB, d time.Duration) (*sql.Tx, error) {
	return beginReadTx(ctx, db, d, sql.LevelRepeatableRead)
}

func beginReadTx(ctx context.Context, db *sql.DB, d time.Duration, iso sql.IsolationLevel) (*sql.Tx, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: iso})
	if err != nil {
		return nil, fmt.Errorf("begin read: %w", err)
	}
	if err := setLocalStatementTimeout(ctx, tx, d); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

// isStatementTimeout reports whether err is a statement canceled by its
// timeout (query_canceled) or by the read's own deadline.
func isStatementTimeout(err error) bool {
	var pqErr *pq.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &pqErr) && pqErr.Code == "57014")
}

// readTimeout returns err unchanged unless it is a statement timeout; then
// it counts and logs the read once (by name only) and returns sentinel, so
// the handler answers 503 QUERY_TIMEOUT. sentinel wraps
// shared.ErrQueryTimeout.
func readTimeout(ctx context.Context, read string, sentinel, err error) error {
	if err == nil || !isStatementTimeout(err) {
		return err
	}
	readTimeouts.WithLabelValues(read).Inc()
	slog.WarnContext(ctx, "interactive read stopped at its statement timeout", "read", read,
		"timeout_ms", interactiveReadTimeout.Milliseconds())
	return sentinel
}
