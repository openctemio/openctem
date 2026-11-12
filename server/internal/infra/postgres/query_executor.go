package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/querylang"
	"github.com/openctemio/openctem/api/pkg/querylang/pgsql"
)

// QueryExecutor runs custom queries (docs/architecture/query-language.md)
// on PostgreSQL. Each statement comes from pgsql.Render (constants and
// bound parameters only) and runs in a READ ONLY transaction with a
// statement timeout and a work_mem cap.
type QueryExecutor struct {
	db      *DB
	timeout time.Duration
}

// InteractiveQueryTimeout is the statement timeout of interactive runs.
const InteractiveQueryTimeout = 5 * time.Second

// queryWorkMem caps sort and hash memory per query.
const queryWorkMem = "32MB"

// NewQueryExecutor returns an executor whose statements time out after
// timeout (InteractiveQueryTimeout when zero).
func NewQueryExecutor(db *DB, timeout time.Duration) *QueryExecutor {
	if timeout <= 0 {
		timeout = InteractiveQueryTimeout
	}
	return &QueryExecutor{db: db, timeout: timeout}
}

var _ querylang.Executor = (*QueryExecutor)(nil)

func (e *QueryExecutor) begin(ctx context.Context) (*sql.Tx, error) {
	tx, err := readTx(ctx, e.db, fmt.Sprintf("%dms", e.timeout.Milliseconds()))
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, "SET LOCAL work_mem = '"+queryWorkMem+"'"); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("set work_mem: %w", err)
	}
	return tx, nil
}

// Explain returns the planner's estimate for the plan's statement.
func (e *QueryExecutor) Explain(ctx context.Context, p *querylang.Plan) (querylang.Estimate, error) {
	var est querylang.Estimate
	st, err := pgsql.Render(p)
	if err != nil {
		return est, err
	}
	tx, err := e.begin(ctx)
	if err != nil {
		return est, err
	}
	defer func() { _ = tx.Rollback() }()
	var raw []byte
	// st.SQL is rendered from constants and placeholders only.
	if err := tx.QueryRowContext(ctx, "EXPLAIN (FORMAT JSON) "+st.SQL, st.Args...).Scan(&raw); err != nil { //nolint:gosec // G202: rendered statement
		return est, mapQueryErr(err)
	}
	var out []struct {
		Plan struct {
			Rows float64 `json:"Plan Rows"`
			Cost float64 `json:"Total Cost"`
		} `json:"Plan"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out) == 0 {
		return est, errors.New("explain: unexpected planner output")
	}
	est.Rows, est.Cost = out[0].Plan.Rows, out[0].Plan.Cost
	return est, nil
}

// Run executes the plan.
func (e *QueryExecutor) Run(ctx context.Context, p *querylang.Plan) (*querylang.Result, error) {
	st, err := pgsql.Render(p)
	if err != nil {
		return nil, err
	}
	tx, err := e.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, st.SQL, st.Args...) //nolint:gosec // G202: rendered statement
	if err != nil {
		return nil, mapQueryErr(err)
	}
	defer func() { _ = rows.Close() }()
	res := &querylang.Result{Columns: p.Columns, Rows: make([][]any, 0, 16)}
	for rows.Next() {
		if len(res.Rows) >= st.Limit {
			res.Truncated = true
			break
		}
		vals := make([]any, len(p.Columns))
		ptrs := make([]any, len(vals))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, fmt.Errorf("scan query row: %w", err)
		}
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				vals[i] = string(b)
			}
		}
		res.Rows = append(res.Rows, vals)
	}
	if err := rows.Err(); err != nil {
		return nil, mapQueryErr(err)
	}
	return res, nil
}

// mapQueryErr turns a statement timeout or cancellation into
// querylang.ErrTimeout.
func mapQueryErr(err error) error {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "57014" { // query_canceled
		return querylang.ErrTimeout
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return querylang.ErrTimeout
	}
	return fmt.Errorf("run query: %w", err)
}

// Match returns the findings a filter-only findings plan selects: the
// number of matches and the first o.Limit ids (oldest first), in the same
// READ ONLY transaction, statement timeout and work_mem cap as Run.
func (e *QueryExecutor) Match(ctx context.Context, p *querylang.Plan, o pgsql.MatchOptions) (*querylang.Matches, error) {
	st, err := pgsql.RenderMatch(p, o)
	if err != nil {
		return nil, err
	}
	tx, err := e.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	m := &querylang.Matches{}
	// Both statements are rendered from constants and placeholders only.
	if err := tx.QueryRowContext(ctx, st.CountSQL, st.Args...).Scan(&m.Total); err != nil { //nolint:gosec // G202: rendered statement
		return nil, mapQueryErr(err)
	}
	rows, err := tx.QueryContext(ctx, st.IDsSQL, st.Args...) //nolint:gosec // G202: rendered statement
	if err != nil {
		return nil, mapQueryErr(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if len(m.IDs) >= st.Limit {
			m.Truncated = true
			break
		}
		var id shared.ID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan match id: %w", err)
		}
		m.IDs = append(m.IDs, id)
	}
	if err := rows.Err(); err != nil {
		return nil, mapQueryErr(err)
	}
	return m, nil
}
