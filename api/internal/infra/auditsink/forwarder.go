package auditsink

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Event types sent to the sink.
const (
	EventAuditRow  = "admin_audit"
	EventChainHead = "admin_audit_chain_head"
)

// QueueSize bounds the events waiting for the sink. A full queue drops the
// newest event (logged and counted): the database keeps every row and the
// next chain head covers it, and an unreachable collector must never slow the
// console down.
const QueueSize = 1000

// sendAttempts per event, with backoff, before it is dropped.
const sendAttempts = 3

// rowEvent is one administrators' audit row and its place in the chain. The
// request body is not sent (it may name things a collector need not hold);
// the hash covers it, so the database row can still be checked against it.
type rowEvent struct {
	Type         string    `json:"type"`
	Position     int64     `json:"position"`
	PrevHash     string    `json:"prev_hash"`
	Hash         string    `json:"hash"`
	ID           string    `json:"id"`
	At           time.Time `json:"at"`
	AdminID      string    `json:"admin_id,omitempty"`
	AdminEmail   string    `json:"admin_email"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resource_type,omitempty"`
	ResourceID   string    `json:"resource_id,omitempty"`
	ResourceName string    `json:"resource_name,omitempty"`
	Method       string    `json:"method,omitempty"`
	Path         string    `json:"path,omitempty"`
	Status       int       `json:"status,omitempty"`
	IP           string    `json:"ip,omitempty"`
	Success      bool      `json:"success"`
	Error        string    `json:"error,omitempty"`
	Severity     string    `json:"severity"`
}

// headEvent is where the chain stood: a later re-signing of the chain cannot
// match a head already sent.
type headEvent struct {
	Type     string    `json:"type"`
	Position int64     `json:"position"`
	Hash     string    `json:"hash"`
	At       time.Time `json:"at"`
}

// ChainHeadReader returns the chain's newest position and hash.
type ChainHeadReader func(ctx context.Context) (int64, string, error)

// Forwarder queues events and delivers them to the sink in order.
type Forwarder struct {
	sink    Sink
	queue   chan []byte
	log     *logger.Logger
	dropped atomic.Int64
	sent    atomic.Int64
	backoff time.Duration
}

// NewForwarder wraps sink.
func NewForwarder(sink Sink, log *logger.Logger) *Forwarder {
	return &Forwarder{sink: sink, queue: make(chan []byte, QueueSize), log: log.With("component", "admin_audit_sink"), backoff: time.Second}
}

// Dropped and Sent are counters for metrics and tests.
func (f *Forwarder) Dropped() int64 { return f.dropped.Load() }
func (f *Forwarder) Sent() int64    { return f.sent.Load() }

// Row queues an audit row (the repository calls it after each insert). It
// never blocks.
func (f *Forwarder) Row(e admin.AuditChainEntry) {
	l := e.Log
	if l == nil {
		return
	}
	ev := rowEvent{
		Type: EventAuditRow, Position: e.Position, PrevHash: e.PrevHash, Hash: e.Hash,
		ID: l.ID.String(), At: l.CreatedAt.UTC(), AdminEmail: l.AdminEmail, Action: l.Action,
		ResourceType: l.ResourceType, ResourceName: l.ResourceName, Method: l.RequestMethod, Path: l.RequestPath,
		Status: l.ResponseStatus, IP: l.IPAddress, Success: l.Success, Error: l.ErrorMessage, Severity: l.Severity,
	}
	if l.AdminID != nil {
		ev.AdminID = l.AdminID.String()
	}
	if l.ResourceID != nil {
		ev.ResourceID = l.ResourceID.String()
	}
	f.enqueue(ev)
}

func (f *Forwarder) enqueue(ev any) {
	b, err := json.Marshal(ev)
	if err != nil {
		f.log.Error("encode admin audit event", "error", err)
		return
	}
	select {
	case f.queue <- b:
	default:
		f.dropped.Add(1)
		f.log.Warn("admin audit sink queue full: event dropped (the database keeps the row)")
	}
}

// Run delivers queued events until ctx ends, then drains what is left for a
// few seconds.
func (f *Forwarder) Run(ctx context.Context) {
	for {
		select {
		case b := <-f.queue:
			f.deliver(ctx, b)
		case <-ctx.Done():
			f.drain()
			return
		}
	}
}

// drain delivers what is still queued, for at most a few seconds, then
// closes the sink.
func (f *Forwarder) drain() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	defer func() { _ = f.sink.Close() }()
	for {
		select {
		case b := <-f.queue:
			f.deliver(ctx, b)
		default:
			return
		}
	}
}

func (f *Forwarder) deliver(ctx context.Context, b []byte) {
	wait := f.backoff
	for attempt := 1; attempt <= sendAttempts; attempt++ {
		sctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := f.sink.Send(sctx, b)
		cancel()
		if err == nil {
			f.sent.Add(1)
			return
		}
		if attempt == sendAttempts || ctx.Err() != nil {
			f.dropped.Add(1)
			f.log.Error("admin audit sink: event not delivered", "error", err, "attempts", attempt)
			return
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
		}
		wait *= 2
	}
}

// ExportHead sends the chain head now and then every interval until ctx ends.
func (f *Forwarder) ExportHead(ctx context.Context, head ChainHeadReader, interval time.Duration) {
	send := func() {
		pos, hash, err := head(ctx)
		if err != nil {
			f.log.Error("read the admin audit chain head", "error", err)
			return
		}
		f.enqueue(headEvent{Type: EventChainHead, Position: pos, Hash: hash, At: time.Now().UTC()})
	}
	send()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			send()
		case <-ctx.Done():
			return
		}
	}
}
