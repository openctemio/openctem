package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Findings read by a compiled RFC-048 filter (docs/rfcs/RFC-048-list-query-contract.md).
// The WHERE clause comes only from filterspec.Compile against
// vulnerability.FindingFields, so it always starts with the tenant predicate
// and carries the caller's data scope.

// findingListTimeout bounds one list, count, stats or SLA statement
// (RFC-048 §3.7): a search or filter that cannot finish in time is a 503
// QUERY_TIMEOUT, never a request that holds a connection for minutes.
const findingListTimeout = "5s"

// maxFindingPageRows is the largest findings page (pagination.New clamps to it).
const maxFindingPageRows = 100

var errUncompiledFindingFilter = errors.New("finding filter was not compiled for the findings registry")

// findingRowQuerier is a connection or a transaction.
type findingRowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// beginFindingRead opens a read-only transaction whose statements stop after
// findingListTimeout. The caller rolls it back (or commits).
func (r *FindingRepository) beginFindingRead(ctx context.Context) (*sql.Tx, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin finding read: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "SET LOCAL statement_timeout = '"+findingListTimeout+"'"); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("set finding read timeout: %w", err)
	}
	return tx, nil
}

// findingTimeout maps a statement timeout (query_canceled) to
// vulnerability.ErrFindingQueryTimeout, so the handler answers a typed 503
// instead of a 500.
func findingTimeout(err error) error {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "57014" {
		return fmt.Errorf("%w: %w", vulnerability.ErrFindingQueryTimeout, err)
	}
	return err
}

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
	tx, err := r.beginFindingRead(ctx)
	if err != nil {
		return empty, err
	}
	defer func() { _ = tx.Rollback() }()

	var total int64
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings WHERE "+w.SQL, w.Args...).Scan(&total); err != nil {
		return empty, findingTimeout(fmt.Errorf("failed to count findings: %w", err))
	}
	query := buildFindingPageQuery(r.selectQuery(), w.SQL, w.OrderBy, page.Limit(), page.Offset())
	rows, err := tx.QueryContext(ctx, query, w.Args...)
	if err != nil {
		return empty, findingTimeout(fmt.Errorf("failed to query findings: %w", err))
	}
	defer rows.Close()
	// A constant capacity: pagination.New caps a page at maxFindingPageRows,
	// and the allocation must not depend on a request value.
	findings := make([]*vulnerability.Finding, 0, maxFindingPageRows)
	for rows.Next() {
		f, err := r.scanFindingFromRows(rows)
		if err != nil {
			return empty, err
		}
		findings = append(findings, f)
	}
	if err := rows.Err(); err != nil {
		return empty, findingTimeout(fmt.Errorf("failed to iterate findings: %w", err))
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
	tx, err := r.beginFindingRead(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var total int64
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings WHERE "+w.SQL, w.Args...).Scan(&total); err != nil {
		return 0, findingTimeout(fmt.Errorf("failed to count findings: %w", err))
	}
	return total, tx.Commit()
}

// GetStatsWhere computes the findings stats over a compiled filter, so the
// numbers count exactly the rows ListWhere lists for the same filter.
func (r *FindingRepository) GetStatsWhere(ctx context.Context, w *filterspec.Where) (*vulnerability.FindingStats, error) {
	if err := checkFindingWhere(w); err != nil {
		return nil, err
	}
	tx, err := r.beginFindingRead(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	stats, err := r.queryFindingStats(ctx, tx, findingStatsSelect+" WHERE "+w.SQL, w.Args)
	if err != nil {
		return nil, findingTimeout(err)
	}
	return stats, tx.Commit()
}

// slaBreakdownSelect counts a filtered population by SLA standing. The age
// buckets partition the past-due findings: the first also takes a missing
// deadline so the buckets always add up to past_due.
const slaBreakdownSelect = `
	SELECT
		COUNT(*),
		COUNT(*) FILTER (WHERE sla_status IN ('exceeded','overdue')),
		COUNT(*) FILTER (WHERE sla_status = 'warning'),
		COUNT(*) FILTER (WHERE sla_status = 'on_track'),
		COUNT(*) FILTER (WHERE sla_status IN ('exceeded','overdue') AND (sla_deadline IS NULL OR sla_deadline > NOW() - INTERVAL '7 days')),
		COUNT(*) FILTER (WHERE sla_status IN ('exceeded','overdue') AND sla_deadline <= NOW() - INTERVAL '7 days' AND sla_deadline > NOW() - INTERVAL '30 days'),
		COUNT(*) FILTER (WHERE sla_status IN ('exceeded','overdue') AND sla_deadline <= NOW() - INTERVAL '30 days' AND sla_deadline > NOW() - INTERVAL '90 days'),
		COUNT(*) FILTER (WHERE sla_status IN ('exceeded','overdue') AND sla_deadline <= NOW() - INTERVAL '90 days'),
		COUNT(*) FILTER (WHERE sla_status IN ('exceeded','overdue') AND severity = 'critical'),
		COUNT(*) FILTER (WHERE sla_status IN ('exceeded','overdue') AND severity = 'high'),
		COUNT(*) FILTER (WHERE sla_status IN ('exceeded','overdue') AND severity = 'medium'),
		COUNT(*) FILTER (WHERE sla_status IN ('exceeded','overdue') AND severity = 'low'),
		COUNT(*) FILTER (WHERE sla_status IN ('exceeded','overdue') AND severity IN ('info','none'))
	FROM findings
`

// GetSLABreakdownWhere counts the findings a compiled filter selects by SLA
// standing. It runs over the same WHERE (tenant, data scope, filters) as
// ListWhere, so its numbers agree with the list.
func (r *FindingRepository) GetSLABreakdownWhere(ctx context.Context, w *filterspec.Where) (*vulnerability.SLABreakdown, error) {
	if err := checkFindingWhere(w); err != nil {
		return nil, err
	}
	b := &vulnerability.SLABreakdown{PastDueBySeverity: map[vulnerability.Severity]int64{}}
	var crit, high, med, low, info int64
	tx, err := r.beginFindingRead(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := tx.QueryRowContext(ctx, slaBreakdownSelect+" WHERE "+w.SQL, w.Args...).Scan(
		&b.Total, &b.PastDue, &b.DueSoon, &b.OnTrack,
		&b.UpTo7, &b.D8to30, &b.D31to90, &b.Over90,
		&crit, &high, &med, &low, &info,
	); err != nil {
		return nil, findingTimeout(fmt.Errorf("failed to get sla breakdown: %w", err))
	}
	b.PastDueBySeverity[vulnerability.SeverityCritical] = crit
	b.PastDueBySeverity[vulnerability.SeverityHigh] = high
	b.PastDueBySeverity[vulnerability.SeverityMedium] = med
	b.PastDueBySeverity[vulnerability.SeverityLow] = low
	b.PastDueBySeverity[vulnerability.SeverityInfo] = info
	return b, tx.Commit()
}

// findingExportTimeout bounds one export statement (RFC-048 §3.7).
const findingExportTimeout = "60s"

// MaxFindingExportBatch is the number of rows one export statement reads.
const MaxFindingExportBatch = 1000

// ExportSortedWhere streams up to limit findings matching a compiled filter,
// in the filter's own order (w.OrderBy, which always ends with the id
// tie-breaker), to emit in batches. All batches read one snapshot (a
// read-only REPEATABLE READ transaction), so a row is never exported twice or
// skipped while findings change, and each statement has a timeout. more says
// whether rows past limit exist. An emit error stops the export.
//
// slotKey (tenant and user) admits one export per key across every API
// replica: a transaction advisory lock, released when the export's
// transaction ends, however it ends. A held slot is
// vulnerability.ErrExportInProgress.
func (r *FindingRepository) ExportSortedWhere(ctx context.Context, w *filterspec.Where, slotKey string, limit int,
	emit func([]*vulnerability.Finding) error,
) (rows int, more bool, err error) {
	if err := checkFindingWhere(w); err != nil {
		return 0, false, err
	}
	if limit <= 0 {
		return 0, false, nil
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return 0, false, fmt.Errorf("begin finding export: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var got bool
	if err := tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(hashtext('findings_export'), hashtext($1))`, slotKey).Scan(&got); err != nil {
		return 0, false, fmt.Errorf("take finding export slot: %w", err)
	}
	if !got {
		return 0, false, vulnerability.ErrExportInProgress
	}
	if _, err := tx.ExecContext(ctx, "SET LOCAL statement_timeout = '"+findingExportTimeout+"'"); err != nil {
		return 0, false, fmt.Errorf("set finding export timeout: %w", err)
	}
	for rows <= limit {
		// One row past the limit tells whether the export is truncated.
		n := min(MaxFindingExportBatch, limit+1-rows)
		query := buildFindingPageQuery(r.selectQuery(), w.SQL, w.OrderBy, n, rows)
		batch, err := r.queryFindingBatch(ctx, tx, query, w.Args, n)
		if err != nil {
			return rows, false, err
		}
		if rows+len(batch) > limit {
			more = true
			batch = batch[:limit-rows]
		}
		if len(batch) > 0 {
			if err := emit(batch); err != nil {
				return rows, more, err
			}
			rows += len(batch)
		}
		if more || len(batch) < n {
			break
		}
	}
	return rows, more, tx.Commit()
}

func (r *FindingRepository) queryFindingBatch(ctx context.Context, tx *sql.Tx, query string, args []any, n int) ([]*vulnerability.Finding, error) {
	res, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to export findings: %w", err)
	}
	defer res.Close()
	out := make([]*vulnerability.Finding, 0, min(n, MaxFindingExportBatch))
	for res.Next() {
		f, err := r.scanFindingFromRows(res)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if err := res.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate exported findings: %w", err)
	}
	return out, nil
}

// maxFindingFacets bounds the COUNT FILTER columns of one CountFacetsWhere.
const maxFindingFacets = 16

// CountFacetsWhere counts, in one statement, the findings matching each
// facet predicate among the rows a compiled filter selects (the quick-view
// counts). w comes from filterspec.CompileFacets: its WHERE is the scoped
// one, and every predicate only narrows it inside COUNT(*) FILTER, so no
// count can reach outside the caller's tenant or data scope. It runs in a
// read-only transaction with the list's statement timeout; a timeout is
// vulnerability.ErrFindingCountTimeout.
func (r *FindingRepository) CountFacetsWhere(ctx context.Context, w *filterspec.Where, preds []string) ([]int64, error) {
	if err := checkFindingWhere(w); err != nil {
		return nil, err
	}
	if len(preds) == 0 || len(preds) > maxFindingFacets {
		return nil, fmt.Errorf("count findings: %d facets (want 1..%d)", len(preds), maxFindingFacets)
	}
	cols := make([]string, len(preds))
	for i, p := range preds {
		cols[i] = "COUNT(*) FILTER (WHERE " + p + ")"
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin finding facet count: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "SET LOCAL statement_timeout = '"+findingListTimeout+"'"); err != nil {
		return nil, fmt.Errorf("set finding facet count timeout: %w", err)
	}
	out := make([]int64, len(preds))
	dest := make([]any, len(preds))
	for i := range out {
		dest[i] = &out[i]
	}
	// The predicates and w.SQL come only from filterspec.CompileFacets
	// (registry SQL, bound values).
	query := "SELECT " + strings.Join(cols, ", ") + " FROM findings WHERE " + w.SQL //nolint:gosec // G202: see above
	if err := tx.QueryRowContext(ctx, query, w.Args...).Scan(dest...); err != nil {
		var pqErr *pq.Error
		if (errors.As(err, &pqErr) && pqErr.Code == "57014") || errors.Is(err, context.DeadlineExceeded) {
			return nil, vulnerability.ErrFindingCountTimeout
		}
		return nil, fmt.Errorf("failed to count finding facets: %w", err)
	}
	return out, tx.Commit()
}

// IDsWhere returns up to limit ids of the findings matching a compiled
// filter, in id order, in one read-only statement with the list timeout.
// Bulk changes by filter select their rows with it.
func (r *FindingRepository) IDsWhere(ctx context.Context, w *filterspec.Where, limit int) ([]shared.ID, error) {
	if err := checkFindingWhere(w); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, nil
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin finding ids: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "SET LOCAL statement_timeout = '"+findingListTimeout+"'"); err != nil {
		return nil, fmt.Errorf("set finding ids timeout: %w", err)
	}
	// w.SQL comes only from filterspec.Compile (registry SQL, bound values).
	query := "SELECT findings.id FROM findings WHERE " + w.SQL + //nolint:gosec // G202: see above
		fmt.Sprintf(" ORDER BY findings.id LIMIT $%d", w.NextArg)
	rows, err := tx.QueryContext(ctx, query, append(append([]any(nil), w.Args...), limit)...)
	if err != nil {
		return nil, fmt.Errorf("failed to select finding ids: %w", err)
	}
	defer rows.Close()
	out := make([]shared.ID, 0, min(limit, 1024))
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		id, err := shared.IDFromString(s)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate finding ids: %w", err)
	}
	return out, tx.Commit()
}

// CountDuplicatesOfWhere counts, per finding id in ids, the findings marked
// as its duplicates (duplicate_of) that match the compiled visibility filter
// w: a duplicate the caller cannot read is not counted. Ids with none are
// absent from the map. Uses idx_findings_duplicate_of.
func (r *FindingRepository) CountDuplicatesOfWhere(ctx context.Context, w *filterspec.Where, ids []shared.ID) (map[shared.ID]int, error) {
	if err := checkFindingWhere(w); err != nil {
		return nil, err
	}
	out := make(map[shared.ID]int, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	idStrs := make([]string, len(ids))
	for i, id := range ids {
		idStrs[i] = id.String()
	}
	args := append(append([]any{}, w.Args...), pq.Array(idStrs))
	query := fmt.Sprintf(`SELECT duplicate_of, COUNT(*) FROM findings
		WHERE %s AND duplicate_of = ANY($%d::uuid[])
		GROUP BY duplicate_of`, w.SQL, w.NextArg)
	tx, err := r.beginFindingRead(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, findingTimeout(fmt.Errorf("failed to count duplicates: %w", err))
	}
	defer rows.Close()
	for rows.Next() {
		var idStr string
		var n int
		if err := rows.Scan(&idStr, &n); err != nil {
			return nil, fmt.Errorf("failed to scan duplicate count: %w", err)
		}
		id, err := shared.IDFromString(idStr)
		if err != nil {
			return nil, fmt.Errorf("invalid finding id %q: %w", idStr, err)
		}
		out[id] = n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate duplicate counts: %w", err)
	}
	return out, tx.Commit()
}
