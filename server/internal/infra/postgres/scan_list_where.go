package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/server/pkg/domain/scan"
	"github.com/openctemio/openctem/server/pkg/domain/scanrun"
	"github.com/openctemio/openctem/server/pkg/filterspec"
	"github.com/openctemio/openctem/server/pkg/pagination"
)

// The scans and runs lists on the list query contract: both read a filter
// compiled by filterspec, so the tenant predicate is always the first
// condition and no request value is part of the SQL text.

const scanListTimeout = "5s"

var (
	errUncompiledScanFilter = errors.New("scan filter was not compiled for a tenant")
	errUncompiledRunFilter  = errors.New("scan run filter was not compiled for a tenant")
)

var (
	_ scan.WhereReader       = (*ScanRepository)(nil)
	_ scanrun.RunWhereReader = (*ScanRunRepository)(nil)
)

// readOnlyTx opens a read-only transaction with a statement timeout.
func readOnlyTx(ctx context.Context, db *DB, what string) (*sql.Tx, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin %s: %w", what, err)
	}
	if _, err := tx.ExecContext(ctx, "SET LOCAL statement_timeout = '"+scanListTimeout+"'"); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("set %s timeout: %w", what, err)
	}
	return tx, nil
}

// ListWhere lists one page of scans matching a compiled filter, with the
// total, in one read-only transaction.
func (r *ScanRepository) ListWhere(ctx context.Context, w *filterspec.Where, page pagination.Pagination) (pagination.Result[*scan.Scan], error) {
	var empty pagination.Result[*scan.Scan]
	if w == nil || !strings.HasPrefix(w.SQL, scan.ListFields.TenantSQL+" = $") || w.OrderBy == "" {
		return empty, errUncompiledScanFilter
	}
	tx, err := readOnlyTx(ctx, r.db, "scan list")
	if err != nil {
		return empty, err
	}
	defer func() { _ = tx.Rollback() }()
	var total int64
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM scans WHERE "+w.SQL, w.Args...).Scan(&total); err != nil {
		return empty, fmt.Errorf("failed to count scans: %w", err)
	}
	// w.SQL and w.OrderBy come from filterspec.Compile (checked above):
	// registry constants and bound placeholders only.
	q := fmt.Sprintf("%s WHERE %s ORDER BY %s LIMIT %d OFFSET %d", //nolint:gosec // G201: compiled filter
		r.selectQuery(), w.SQL, w.OrderBy, page.Limit(), page.Offset())
	rows, err := tx.QueryContext(ctx, q, w.Args...)
	if err != nil {
		return empty, fmt.Errorf("failed to list scans: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var scans []*scan.Scan
	for rows.Next() {
		s, err := r.scanFromRows(rows)
		if err != nil {
			return empty, err
		}
		scans = append(scans, s)
	}
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("failed to list scans: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return empty, fmt.Errorf("commit scan list: %w", err)
	}
	return pagination.NewResult(scans, total, page), nil
}

// ListWhere lists one page of runs matching a compiled filter, with the
// total, in one read-only transaction.
func (r *ScanRunRepository) ListWhere(ctx context.Context, w *filterspec.Where, page pagination.Pagination) (pagination.Result[*scanrun.Run], error) {
	var empty pagination.Result[*scanrun.Run]
	if w == nil || !strings.HasPrefix(w.SQL, scanrun.RunFields.TenantSQL+" = $") || w.OrderBy == "" {
		return empty, errUncompiledRunFilter
	}
	tx, err := readOnlyTx(ctx, r.db, "scan run list")
	if err != nil {
		return empty, err
	}
	defer func() { _ = tx.Rollback() }()
	var total int64
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM scan_runs WHERE "+w.SQL, w.Args...).Scan(&total); err != nil {
		return empty, fmt.Errorf("failed to count pipeline runs: %w", err)
	}
	q := fmt.Sprintf("%s WHERE %s ORDER BY %s LIMIT %d OFFSET %d", //nolint:gosec // G201: compiled filter
		r.selectQuery(), w.SQL, w.OrderBy, page.Limit(), page.Offset())
	rows, err := tx.QueryContext(ctx, q, w.Args...)
	if err != nil {
		return empty, fmt.Errorf("failed to list pipeline runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var runs []*scanrun.Run
	for rows.Next() {
		run, err := r.scanRunFromRows(rows)
		if err != nil {
			return empty, err
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return empty, err
	}
	if err := tx.Commit(); err != nil {
		return empty, fmt.Errorf("commit scan run list: %w", err)
	}
	return pagination.NewResult(runs, total, page), nil
}
