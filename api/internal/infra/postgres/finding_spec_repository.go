package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Findings read by a compiled RFC-048 filter (docs/rfcs/RFC-048-list-query-contract.md).
// The WHERE clause comes only from filterspec.Compile against
// vulnerability.FindingFields, so it always starts with the tenant predicate
// and carries the caller's data scope.

// findingListTimeout bounds one list or count statement (RFC-048 §3.7).
const findingListTimeout = "5s"

var errUncompiledFindingFilter = errors.New("finding filter was not compiled for the findings registry")

// checkFindingWhere is defense in depth: a WHERE that does not start with the
// findings tenant predicate did not come from Compile and is refused.
func checkFindingWhere(w *filterspec.Where) error {
	if w == nil || !strings.HasPrefix(w.SQL, vulnerability.FindingFields.TenantSQL+" = $") || w.OrderBy == "" {
		return errUncompiledFindingFilter
	}
	return nil
}

// ListWhere lists one page of findings matching a compiled filter, with the
// total, in one read-only transaction with a statement timeout.
func (r *FindingRepository) ListWhere(ctx context.Context, w *filterspec.Where, page pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	var empty pagination.Result[*vulnerability.Finding]
	if err := checkFindingWhere(w); err != nil {
		return empty, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return empty, fmt.Errorf("begin finding list: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "SET LOCAL statement_timeout = '"+findingListTimeout+"'"); err != nil {
		return empty, fmt.Errorf("set finding list timeout: %w", err)
	}

	var total int64
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings WHERE "+w.SQL, w.Args...).Scan(&total); err != nil {
		return empty, fmt.Errorf("failed to count findings: %w", err)
	}
	query := buildFindingPageQuery(r.selectQuery(), w.SQL, w.OrderBy, page.Limit(), page.Offset())
	rows, err := tx.QueryContext(ctx, query, w.Args...)
	if err != nil {
		return empty, fmt.Errorf("failed to query findings: %w", err)
	}
	defer rows.Close()
	findings := make([]*vulnerability.Finding, 0, page.Limit())
	for rows.Next() {
		f, err := r.scanFindingFromRows(rows)
		if err != nil {
			return empty, err
		}
		findings = append(findings, f)
	}
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("failed to iterate findings: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return empty, fmt.Errorf("commit finding list: %w", err)
	}
	return pagination.NewResult(findings, total, page), nil
}

// CountWhere counts the findings matching a compiled filter.
func (r *FindingRepository) CountWhere(ctx context.Context, w *filterspec.Where) (int64, error) {
	if err := checkFindingWhere(w); err != nil {
		return 0, err
	}
	var total int64
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings WHERE "+w.SQL, w.Args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("failed to count findings: %w", err)
	}
	return total, nil
}

// GetStatsWhere computes the findings stats over a compiled filter, so the
// numbers count exactly the rows ListWhere lists for the same filter.
func (r *FindingRepository) GetStatsWhere(ctx context.Context, w *filterspec.Where) (*vulnerability.FindingStats, error) {
	if err := checkFindingWhere(w); err != nil {
		return nil, err
	}
	return r.queryFindingStats(ctx, findingStatsSelect+" WHERE "+w.SQL, w.Args)
}
