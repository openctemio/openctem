// Package auditsink streams the platform administrators' audit log off the
// box (RFC-022).
//
// admin_audit_logs is append-only and hash-chained inside the database, but a
// database administrator (or anyone who restores an older backup) can still
// rewrite the whole chain consistently. A copy that lives somewhere the
// database operator cannot write closes that gap: the sink holds every row
// and the chain head (position and hash) as it was when sent, so a rewrite
// shows up as a head that no longer matches.
//
// The forwarder is an exclusive controller. Each run it reads the rows after
// a durable cursor in bounded batches, sends each batch to the sink, and
// moves the cursor only after the sink accepted it: delivery is at-least-once,
// so a receiver must treat a repeated chain position as a duplicate (the batch
// id names the range). Failures back off exponentially. When nothing is new
// it still sends the chain head every HeadInterval, so a silent sink is
// itself an alarm. It verifies the chain on a timer and carries the result
// (an honest "verified" flag: false until a verification ran, and again
// after one failed to run) in every export, in metrics and in an error log.
//
// Destinations (ADMIN_AUDIT_SINK):
//
//	https://collector.example/path   one signed JSON batch per POST
//	syslog+tls://host:6514           RFC 5424 over TLS (RFC 5425), optional mTLS
//	file:///var/log/openctem/admin-audit.jsonl   one JSON batch per line
//
// The destination is an operator setting (environment only), never something
// a console user can change. The webhook secret is never logged.
package auditsink

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Row is one admin_audit_logs row as shipped: the audit entry and its place
// in the hash chain. The shipped columns are explicit (see rowEvent); the
// request body and user agent are withheld.
type Row = admin.AuditChainEntry

// Head is the chain tail: the newest position and its hash.
type Head struct {
	Position int64  `json:"position"`
	Hash     string `json:"hash"`
}

// Cursor is the last acknowledged row.
type Cursor struct {
	Position int64
	Hash     string
}

// Store is the database side.
type Store interface {
	// ReadForwardRows returns up to limit chain rows after position, oldest first.
	ReadForwardRows(ctx context.Context, after int64, limit int) ([]Row, error)
	// ChainHead returns the chain's newest position and hash.
	ChainHead(ctx context.Context) (int64, string, error)
	LoadForwardCursor(ctx context.Context) (Cursor, error)
	// SaveForwardCursor only moves the cursor forward.
	SaveForwardCursor(ctx context.Context, c Cursor) error
}

// Verifier is the chain verification (AuditLogRepository.VerifyChain).
type Verifier interface {
	VerifyChain(ctx context.Context) (*admin.AuditChainReport, error)
}

// ChainStatus is the verification result carried in every export.
type ChainStatus struct {
	// Verified is false until the first verification ran.
	Verified   bool       `json:"verified"`
	OK         bool       `json:"ok"`
	Breaks     int        `json:"breaks"`
	Truncated  bool       `json:"truncated,omitempty"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
}

// Batch is one delivery: rows (possibly none, for a head-only export), the
// chain head and the verification state.
type Batch struct {
	SentAt time.Time
	Rows   []Row
	Head   Head
	Chain  ChainStatus
	// Gap is set when the first row does not continue the last delivered row.
	Gap *Gap
}

// Gap says how a batch fails to continue the cursor: rows were removed or
// rewritten between the last delivered row and this one.
type Gap struct {
	ExpectedPosition int64 `json:"expected_position"`
	FirstPosition    int64 `json:"first_position"`
	PrevHashMatches  bool  `json:"prev_hash_matches"`
}

// ID names the range, for the receiver's de-duplication.
func (b Batch) ID() string {
	if len(b.Rows) == 0 {
		return fmt.Sprintf("head-%d", b.Head.Position)
	}
	return fmt.Sprintf("%d-%d", b.Rows[0].Position, b.Rows[len(b.Rows)-1].Position)
}

// Sink delivers a batch; nil means the sink accepted it.
type Sink interface {
	Name() string
	Send(ctx context.Context, b Batch) error
	Close() error
}

// Config tunes the forwarder.
type Config struct {
	Interval       time.Duration // run period and base retry delay (default 15s)
	BatchSize      int           // rows per delivery (default 500, max 5000)
	MaxBatchesRun  int           // deliveries per run (default 10)
	HeadInterval   time.Duration // head export when idle (default 1h)
	VerifyInterval time.Duration // chain verification period (default 1h)
	LagAlert       time.Duration // oldest unsent row age that raises the alarm (default 10m)
	MaxBackoff     time.Duration // retry delay cap (default 15m)
	Logger         *logger.Logger
}

const (
	maxBatchSize = 5000
	// verifyRetry is how soon a verification that could not run is retried.
	verifyRetry = 5 * time.Minute
)

func (c *Config) defaults() {
	if c.Interval <= 0 {
		c.Interval = 15 * time.Second
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 500
	}
	if c.BatchSize > maxBatchSize {
		c.BatchSize = maxBatchSize
	}
	if c.MaxBatchesRun <= 0 {
		c.MaxBatchesRun = 10
	}
	if c.HeadInterval <= 0 {
		c.HeadInterval = time.Hour
	}
	if c.VerifyInterval <= 0 {
		c.VerifyInterval = time.Hour
	}
	if c.LagAlert <= 0 {
		c.LagAlert = 10 * time.Minute
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = 15 * time.Minute
	}
	if c.Logger == nil {
		c.Logger = logger.NewNop()
	}
}

// Forwarder is the controller. Reconcile runs serially (one controller lease
// holder at a time), so its state needs no lock.
type Forwarder struct {
	store    Store
	verifier Verifier
	sink     Sink
	cfg      Config
	log      *logger.Logger
	now      func() time.Time

	failures    int
	nextAttempt time.Time
	lastHead    time.Time
	nextVerify  time.Time
	chain       ChainStatus
	lagAlerted  bool
	chainAlert  bool
}

// NewForwarder builds the forwarder.
func NewForwarder(store Store, verifier Verifier, sink Sink, cfg Config) (*Forwarder, error) {
	if store == nil || verifier == nil {
		return nil, errors.New("auditsink: store and verifier are required")
	}
	if sink == nil {
		return nil, errors.New("auditsink: no sink configured")
	}
	cfg.defaults()
	return &Forwarder{store: store, verifier: verifier, sink: sink, cfg: cfg,
		log: cfg.Logger.With("controller", "admin-audit-sink"), now: time.Now}, nil
}

// Name implements controller.Controller.
func (f *Forwarder) Name() string { return "admin-audit-sink" }

// Interval implements controller.Controller.
func (f *Forwarder) Interval() time.Duration { return f.cfg.Interval }

// Exclusive makes the manager run one replica at a time, so two replicas do
// not race on the cursor.
func (f *Forwarder) Exclusive() bool { return true }

// Reconcile ships what is new. It returns the number of rows delivered.
func (f *Forwarder) Reconcile(ctx context.Context) (int, error) {
	now := f.now()
	if now.Before(f.nextAttempt) {
		return 0, nil
	}
	f.verifyIfDue(ctx, now)

	cur, err := f.store.LoadForwardCursor(ctx)
	if err != nil {
		return 0, f.fail(now, "", fmt.Errorf("load cursor: %w", err))
	}
	sent := 0
	for i := 0; i < f.cfg.MaxBatchesRun; i++ {
		rows, err := f.store.ReadForwardRows(ctx, cur.Position, f.cfg.BatchSize)
		if err != nil {
			return sent, f.fail(now, "", fmt.Errorf("read rows: %w", err))
		}
		if len(rows) == 0 {
			break
		}
		head, err := f.chainHead(ctx)
		if err != nil {
			return sent, f.fail(now, "", err)
		}
		gap := f.continuity(cur, rows)
		if name, err := f.deliver(ctx, Batch{SentAt: f.now(), Rows: rows, Head: head, Chain: f.chain, Gap: gap}); err != nil {
			return sent, f.fail(now, name, err)
		}
		last := rows[len(rows)-1]
		cur = Cursor{Position: last.Position, Hash: last.Hash}
		sent += len(rows)
		f.lastHead = now
		metrics.AdminAuditForwardRows.Add(float64(len(rows)))
		if err := f.store.SaveForwardCursor(ctx, cur); err != nil {
			// The rows are delivered; the next run re-sends them (at-least-once).
			return sent, f.fail(now, "", fmt.Errorf("save cursor: %w", err))
		}
	}

	head, err := f.chainHead(ctx)
	if err != nil {
		return sent, f.fail(now, "", err)
	}
	pending, err := f.store.ReadForwardRows(ctx, cur.Position, 1)
	if err != nil {
		return sent, f.fail(now, "", fmt.Errorf("read rows: %w", err))
	}
	if len(pending) == 0 && now.Sub(f.lastHead) >= f.cfg.HeadInterval {
		if name, err := f.deliver(ctx, Batch{SentAt: f.now(), Head: head, Chain: f.chain}); err != nil {
			return sent, f.fail(now, name, err)
		}
		f.lastHead = now
	}
	f.succeed(now, head, cur, pending)
	return sent, nil
}

// continuity checks that the first row follows the cursor row, by position and
// by hash link. A break is reported (log, metric, batch payload) but delivery
// goes on: the off-box copy must not stall behind a tampered chain.
func (f *Forwarder) continuity(cur Cursor, rows []Row) *Gap {
	if cur.Position == 0 && cur.Hash == "" {
		return nil // nothing delivered yet
	}
	r := rows[0]
	posOK, hashOK := r.Position == cur.Position+1, r.PrevHash == cur.Hash
	if posOK && hashOK {
		return nil
	}
	metrics.AdminAuditForwardGaps.Inc()
	f.log.Error("admin_audit_forward_gap: the next row does not continue the last delivered row",
		"expected_position", cur.Position+1, "first_position", r.Position, "prev_hash_matches", hashOK)
	return &Gap{ExpectedPosition: cur.Position + 1, FirstPosition: r.Position, PrevHashMatches: hashOK}
}

func (f *Forwarder) chainHead(ctx context.Context) (Head, error) {
	pos, hash, err := f.store.ChainHead(ctx)
	if err != nil {
		return Head{}, fmt.Errorf("read chain head: %w", err)
	}
	return Head{Position: pos, Hash: hash}, nil
}

// deliver sends the batch with a bounded wait; it names the sink on failure.
func (f *Forwarder) deliver(ctx context.Context, b Batch) (string, error) {
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := f.sink.Send(sctx, b); err != nil {
		return f.sink.Name(), err
	}
	return "", nil
}

// Close releases the sink's connection (called when the process stops).
func (f *Forwarder) Close() error { return f.sink.Close() }

func (f *Forwarder) fail(now time.Time, sink string, err error) error {
	f.failures++
	delay := f.cfg.Interval
	for i := 1; i < f.failures && delay < f.cfg.MaxBackoff; i++ {
		delay *= 2
	}
	if delay > f.cfg.MaxBackoff {
		delay = f.cfg.MaxBackoff
	}
	f.nextAttempt = now.Add(delay)
	if sink == "" {
		sink = "store"
	}
	metrics.AdminAuditForwardFailures.WithLabelValues(sink).Inc()
	metrics.AdminAuditForwardConsecutiveFailures.Set(float64(f.failures))
	// err comes from the sink, which strips the URL and never include the secret.
	f.log.Error("admin audit forward failed", "sink", sink, "consecutive_failures", f.failures,
		"retry_in", delay.String(), "error", err.Error())
	return err
}

func (f *Forwarder) succeed(now time.Time, head Head, cur Cursor, pending []Row) {
	f.failures = 0
	f.nextAttempt = time.Time{}
	metrics.AdminAuditForwardConsecutiveFailures.Set(0)
	metrics.AdminAuditForwardLastSuccess.Set(float64(now.Unix()))

	lagRows := head.Position - cur.Position
	if lagRows < 0 {
		lagRows = 0
	}
	var lag time.Duration
	if len(pending) > 0 {
		lag = now.Sub(pending[0].Log.CreatedAt)
	}
	metrics.AdminAuditForwardLagRows.Set(float64(lagRows))
	metrics.AdminAuditForwardLagSeconds.Set(lag.Seconds())
	switch {
	case lag > f.cfg.LagAlert && !f.lagAlerted:
		f.lagAlerted = true
		f.log.Error("admin audit forwarder is lagging", "lag_rows", lagRows, "oldest_unsent_age", lag.String())
	case lag <= f.cfg.LagAlert:
		f.lagAlerted = false
	}
}

func (f *Forwarder) verifyIfDue(ctx context.Context, now time.Time) {
	if now.Before(f.nextVerify) {
		return
	}
	rep, err := f.verifier.VerifyChain(ctx)
	if err != nil {
		metrics.AdminAuditChainVerifyErrors.Inc()
		f.log.Error("admin audit chain verification could not run", "error", err.Error())
		// A result from before the failure must not keep vouching for the
		// chain: the export says it is not verified. The run is retried
		// within minutes, not on every run.
		f.chain = ChainStatus{Verified: false}
		retry := verifyRetry
		if f.cfg.VerifyInterval < retry {
			retry = f.cfg.VerifyInterval
		}
		f.nextVerify = now.Add(retry)
		return
	}
	f.nextVerify = now.Add(f.cfg.VerifyInterval)
	at := rep.VerifiedAt
	f.chain = ChainStatus{Verified: true, OK: rep.OK(), Breaks: len(rep.Breaks), Truncated: rep.Truncated, VerifiedAt: &at}
	if rep.OK() {
		metrics.AdminAuditChainOK.Set(1)
		f.chainAlert = false
		return
	}
	metrics.AdminAuditChainOK.Set(0)
	if !f.chainAlert {
		metrics.AdminAuditChainBreaks.Add(float64(len(rep.Breaks)))
	}
	f.chainAlert = true
	args := []any{"breaks", len(rep.Breaks)}
	if len(rep.Breaks) > 0 {
		first := rep.Breaks[0]
		args = append(args, "first_position", first.Position, "first_reason", first.Reason)
	}
	f.log.Error("admin_audit_chain_break: the administrators' audit chain does not verify", args...)
}
