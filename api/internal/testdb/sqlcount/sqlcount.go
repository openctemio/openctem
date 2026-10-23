// Package sqlcount opens a database/sql handle that counts the statements
// sent to PostgreSQL, so a test can budget how many round trips an operation
// makes (an import that quietly turns into one query per finding shows up as
// a count, long before it shows up as latency).
//
// What counts: every Exec and Query, and every execution of a prepared
// statement. A COPY counts once, however many rows it streams. Transactions
// are counted separately (BEGIN and COMMIT are not statements). Nothing here
// reads the values of arguments or rows.
package sqlcount

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strings"
	"sync"
	"time"

	"github.com/lib/pq"
)

// Counter accumulates the counts of every connection opened with it. It is
// safe for concurrent use.
type Counter struct {
	mu         sync.Mutex
	statements int
	txs        int
	verbs      map[string]int
}

// Snapshot is a copy of the counts at one moment.
type Snapshot struct {
	Statements   int
	Transactions int
	// Verbs counts statements by their first keyword (SELECT, INSERT, UPDATE,
	// DELETE, WITH, ...), upper case.
	Verbs map[string]int
}

// Snapshot returns the counts so far.
func (c *Counter) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := make(map[string]int, len(c.verbs))
	for k, n := range c.verbs {
		v[k] = n
	}
	return Snapshot{Statements: c.statements, Transactions: c.txs, Verbs: v}
}

// Settle waits until no statement has been counted for quiet (an operation
// that hands work to a goroutine, such as an audit write after the call
// returned, is not finished when the call is), then returns the counts. It
// gives up after max and returns what it has.
func (c *Counter) Settle(quiet, max time.Duration) Snapshot {
	deadline := time.Now().Add(max)
	last := c.Snapshot().Statements
	stableSince := time.Now()
	for time.Now().Before(deadline) {
		time.Sleep(quiet / 5)
		if n := c.Snapshot().Statements; n != last {
			last, stableSince = n, time.Now()
			continue
		}
		if time.Since(stableSince) >= quiet {
			break
		}
	}
	return c.Snapshot()
}

// Reset zeroes the counts.
func (c *Counter) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.statements, c.txs, c.verbs = 0, 0, nil
}

func (c *Counter) statement(query string) {
	v := verb(query)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.statements++
	if c.verbs == nil {
		c.verbs = map[string]int{}
	}
	c.verbs[v]++
}

func (c *Counter) tx() {
	c.mu.Lock()
	c.txs++
	c.mu.Unlock()
}

// verb is the first keyword of a statement, after leading whitespace and
// SQL comments.
func verb(query string) string {
	q := query
	for {
		q = strings.TrimSpace(q)
		switch {
		case strings.HasPrefix(q, "--"):
			i := strings.IndexByte(q, '\n')
			if i < 0 {
				return "OTHER"
			}
			q = q[i+1:]
		case strings.HasPrefix(q, "/*"):
			i := strings.Index(q, "*/")
			if i < 0 {
				return "OTHER"
			}
			q = q[i+2:]
		default:
			end := strings.IndexFunc(q, func(r rune) bool { return r == ' ' || r == '\n' || r == '\t' || r == '(' || r == ';' })
			if end < 0 {
				end = len(q)
			}
			if end == 0 {
				return "OTHER"
			}
			return strings.ToUpper(q[:end])
		}
	}
}

// Open opens dsn with the lib/pq driver and counts into c.
func Open(dsn string, c *Counter) (*sql.DB, error) {
	inner, err := pq.NewConnector(dsn)
	if err != nil {
		return nil, err
	}
	return sql.OpenDB(&connector{inner: inner, c: c}), nil
}

type connector struct {
	inner driver.Connector
	c     *Counter
}

func (k *connector) Connect(ctx context.Context) (driver.Conn, error) {
	cn, err := k.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &conn{Conn: cn, c: k.c}, nil
}

func (k *connector) Driver() driver.Driver { return k.inner.Driver() }

// conn forwards everything the pq connection supports, counting statements.
type conn struct {
	driver.Conn
	c *Counter
}

func (cn *conn) Prepare(query string) (driver.Stmt, error) {
	st, err := cn.Conn.Prepare(query)
	if err != nil {
		return nil, err
	}
	return &stmt{Stmt: st, c: cn.c, query: query}, nil
}

func (cn *conn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	pc, ok := cn.Conn.(driver.ConnPrepareContext)
	if !ok {
		return cn.Prepare(query)
	}
	st, err := pc.PrepareContext(ctx, query)
	if err != nil {
		return nil, err
	}
	return &stmt{Stmt: st, c: cn.c, query: query}, nil
}

func (cn *conn) Begin() (driver.Tx, error) {
	cn.c.tx()
	return cn.Conn.Begin() //nolint:staticcheck // forwarded as the interface requires
}

func (cn *conn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	bt, ok := cn.Conn.(driver.ConnBeginTx)
	if !ok {
		return cn.Begin()
	}
	cn.c.tx()
	return bt.BeginTx(ctx, opts)
}

func (cn *conn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	ec, ok := cn.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	cn.c.statement(query)
	return ec.ExecContext(ctx, query, args)
}

func (cn *conn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	qc, ok := cn.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	cn.c.statement(query)
	return qc.QueryContext(ctx, query, args)
}

func (cn *conn) Ping(ctx context.Context) error {
	if p, ok := cn.Conn.(driver.Pinger); ok {
		return p.Ping(ctx)
	}
	return nil
}

func (cn *conn) ResetSession(ctx context.Context) error {
	if r, ok := cn.Conn.(driver.SessionResetter); ok {
		return r.ResetSession(ctx)
	}
	return nil
}

func (cn *conn) IsValid() bool {
	if v, ok := cn.Conn.(driver.Validator); ok {
		return v.IsValid()
	}
	return true
}

func (cn *conn) CheckNamedValue(nv *driver.NamedValue) error {
	if ck, ok := cn.Conn.(driver.NamedValueChecker); ok {
		return ck.CheckNamedValue(nv)
	}
	return driver.ErrSkip
}

// stmt counts each execution of a prepared statement. The rows of a COPY
// stream through repeated Exec calls and count once, at the first.
type stmt struct {
	driver.Stmt
	c     *Counter
	query string
	seen  bool
}

func (s *stmt) count() {
	if verb(s.query) == "COPY" {
		if s.seen {
			return
		}
		s.seen = true
	}
	s.c.statement(s.query)
}

func (s *stmt) Exec(args []driver.Value) (driver.Result, error) {
	s.count()
	return s.Stmt.Exec(args) //nolint:staticcheck // forwarded as the interface requires
}

func (s *stmt) Query(args []driver.Value) (driver.Rows, error) {
	s.count()
	return s.Stmt.Query(args) //nolint:staticcheck // forwarded as the interface requires
}

func (s *stmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	s.count()
	if ec, ok := s.Stmt.(driver.StmtExecContext); ok {
		return ec.ExecContext(ctx, args)
	}
	vals := make([]driver.Value, len(args))
	for i, a := range args {
		vals[i] = a.Value
	}
	return s.Stmt.Exec(vals) //nolint:staticcheck // fallback for a driver without contexts
}

func (s *stmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	s.count()
	if qc, ok := s.Stmt.(driver.StmtQueryContext); ok {
		return qc.QueryContext(ctx, args)
	}
	vals := make([]driver.Value, len(args))
	for i, a := range args {
		vals[i] = a.Value
	}
	return s.Stmt.Query(vals) //nolint:staticcheck // fallback for a driver without contexts
}
