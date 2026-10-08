// Package commandlog keeps the per-task logs sensors send (sensor protocol
// v2, POST /api/v2/sensor/commands/{id}/logs; docs/rfcs/RFC-029-sensor-
// protocol-v2-and-sdk-stability.md §4.4.1) and serves them to the run page.
//
// A sensor's log lines are hostile input: the platform never trusts the
// sensor's own redaction or sanitizing. Every line is cut to the limits,
// stripped of control and bidi-override characters and run through the
// platform's secret redactor before it is stored; the web shows it as plain
// text. Writes are bounded per batch (500 lines, 256 KiB on the wire) and
// per command (200 batches, 2 MiB); a sensor may write only to a command of
// its own tenant that it holds or held, and the tenant always comes from its
// authenticated identity.
package commandlog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/internal/app/validation"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/safetext"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// Limits of the logs resource.
const (
	// MaxLinesPerBatch caps the lines of one batch.
	MaxLinesPerBatch = protov2.MaxLogLinesPerBatch
	// MaxSeq bounds the batch sequence number (exclusive).
	MaxSeq = protov2.MaxLogSeq
	// MaxBatchesPerCommand and MaxBytesPerCommand cap what one command
	// stores; beyond them batches are counted as dropped, never stored.
	MaxBatchesPerCommand = 200
	MaxBytesPerCommand   = 2 << 20
	// MaxReadLines caps what one read returns.
	MaxReadLines = 5000
	// AcceptAfterFinish is how long after a command finished its logs are
	// still accepted (an outbox replaying after an outage).
	AcceptAfterFinish = 24 * time.Hour
	// Retention is how long stored logs are kept.
	Retention = 14 * 24 * time.Hour

	maxMsgBytes      = 8 << 10
	maxFields        = 32
	maxFieldKeyBytes = 128
	maxFieldValBytes = 1 << 10
	maxSourceBytes   = 64
)

// Errors of Append. ErrNotFound answers every "not yours" case alike (no
// oracle for another tenant's or another sensor's command).
var (
	ErrNotFound = fmt.Errorf("%w: command not found", shared.ErrNotFound)
	// ErrClosed: the command finished more than AcceptAfterFinish ago.
	ErrClosed = errors.New("command logs closed")
)

// Levels.
const (
	LevelDebug = "debug"
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

// RawLine is one line as the sensor sent it.
type RawLine struct {
	TS     string                     `json:"ts"`
	Level  string                     `json:"level"`
	Msg    string                     `json:"msg"`
	Source string                     `json:"source"`
	Fields map[string]json.RawMessage `json:"fields"`
}

// Line is one stored line.
type Line struct {
	TS     time.Time      `json:"ts"`
	Level  string         `json:"level"`
	Msg    string         `json:"msg"`
	Source string         `json:"source,omitempty"`
	Fields map[string]any `json:"fields,omitempty"`
}

// Batch is one sanitized batch ready to store.
type Batch struct {
	TenantID  shared.ID
	SensorID  shared.ID
	CommandID shared.ID
	Seq       int
	Lines     []Line
	// JSON is Lines encoded; Bytes counts toward the per-command cap.
	JSON []byte
}

// AppendResult answers a batch.
type AppendResult struct {
	Stored    int  `json:"stored"`
	Dropped   int  `json:"dropped"`
	Truncated bool `json:"truncated"`
}

// Page is what a read returns.
type Page struct {
	Lines     []Line `json:"lines"`
	Truncated bool   `json:"truncated"`
	// Platform: the command is a platform job, its lines were written by a
	// shared platform sensor (the read masks the sensor's own details).
	Platform bool `json:"-"`
}

// shown is p as a tenant may read it: a platform sensor's own addresses and
// paths masked (sensordom.RedactPlatformText), and never nil lines.
func shown(p Page) Page {
	if p.Lines == nil {
		p.Lines = []Line{}
	}
	if !p.Platform {
		return p
	}
	for i := range p.Lines {
		l := &p.Lines[i]
		l.Msg = sensordom.RedactPlatformText(l.Msg)
		l.Source = sensordom.RedactPlatformText(l.Source)
		for k, v := range l.Fields {
			l.Fields[k] = sensordom.RedactPlatformValue(v)
		}
	}
	return p
}

// Store persists batches (*postgres.CommandLogRepository).
type Store interface {
	// Append stores b unless the command is not the sensor's (ErrNotFound)
	// or finished too long ago (ErrClosed). A replay of a stored seq
	// answers the stored count; a batch past the per-command caps is
	// counted as dropped.
	Append(ctx context.Context, b Batch, acceptAfterFinish time.Duration, maxBatches, maxBytes int) (AppendResult, error)
	// ListForRunTask returns the logs of command commandID of run runID in
	// tenantID (ErrNotFound when the command is not a task of that run of
	// that tenant), at most maxLines lines.
	ListForRunTask(ctx context.Context, tenantID, runID, commandID shared.ID, maxLines int) (Page, error)
}

// Service validates, sanitizes and stores log batches.
type Service struct {
	store    Store
	redactor *validation.Redactor
	now      func() time.Time
}

// NewService builds the service.
func NewService(store Store) *Service {
	r := validation.NewRedactor()
	// The platform's own credentials: sensor keys and API keys.
	r.AddPattern(`octs_[A-Za-z0-9_-]{16,}`)
	r.AddPattern(`oct_[A-Za-z0-9_-]{16,}`)
	r.AddPattern(`rda_[A-Za-z0-9_-]{16,}`)
	// key=value and "key":"value" forms of common secret names (tool logs
	// print configuration and JSON).
	r.AddPattern(`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)"?\s*[:=]\s*"?[^\s",}&]+`)
	return &Service{store: store, redactor: r, now: time.Now}
}

// AppendInput is one batch from a sensor. TenantID and SensorID come from
// the sensor's authenticated identity.
type AppendInput struct {
	TenantID  shared.ID
	SensorID  shared.ID
	CommandID shared.ID
	Seq       int
	Lines     []RawLine
}

// Append sanitizes and stores one batch.
func (s *Service) Append(ctx context.Context, in AppendInput) (AppendResult, error) {
	if in.TenantID.IsZero() || in.SensorID.IsZero() || in.CommandID.IsZero() {
		return AppendResult{}, fmt.Errorf("%w: tenant, sensor and command are required", shared.ErrValidation)
	}
	if in.Seq < 0 || in.Seq >= MaxSeq {
		return AppendResult{}, fmt.Errorf("%w: seq must be between 0 and %d", shared.ErrValidation, MaxSeq-1)
	}
	if len(in.Lines) > MaxLinesPerBatch {
		return AppendResult{}, fmt.Errorf("%w: at most %d lines per batch", shared.ErrValidation, MaxLinesPerBatch)
	}
	lines := make([]Line, 0, len(in.Lines))
	now := s.now().UTC()
	for _, raw := range in.Lines {
		lines = append(lines, s.sanitize(raw, now))
	}
	b, err := json.Marshal(lines)
	if err != nil {
		return AppendResult{}, fmt.Errorf("encode lines: %w", err)
	}
	return s.store.Append(ctx, Batch{TenantID: in.TenantID, SensorID: in.SensorID, CommandID: in.CommandID,
		Seq: in.Seq, Lines: lines, JSON: b}, AcceptAfterFinish, MaxBatchesPerCommand, MaxBytesPerCommand)
}

// ListForRunTask returns a task's logs for the run page.
func (s *Service) ListForRunTask(ctx context.Context, tenantID, runID, commandID shared.ID) (Page, error) {
	if tenantID.IsZero() || runID.IsZero() || commandID.IsZero() {
		return Page{}, ErrNotFound
	}
	p, err := s.store.ListForRunTask(ctx, tenantID, runID, commandID, MaxReadLines)
	if err != nil {
		return Page{}, err
	}
	return shown(p), nil
}

// ListForCommand returns any command's logs (scan, retest, validate,
// system). The caller checks who may read them (CommandSubject).
func (s *Service) ListForCommand(ctx context.Context, tenantID, commandID shared.ID) (Page, error) {
	if tenantID.IsZero() || commandID.IsZero() {
		return Page{}, ErrNotFound
	}
	r, ok := s.store.(commandReader)
	if !ok {
		return Page{}, ErrNotFound
	}
	p, err := r.ListForCommand(ctx, tenantID, commandID, MaxReadLines)
	if err != nil {
		return Page{}, err
	}
	return shown(p), nil
}

// CommandSubject is the finding a command is about (a retest or a
// validate job), nil for any other command.
func (s *Service) CommandSubject(ctx context.Context, tenantID, commandID shared.ID) (*shared.ID, error) {
	r, ok := s.store.(commandReader)
	if !ok {
		return nil, nil
	}
	return r.SubjectFinding(ctx, tenantID, commandID)
}

// commandReader reads a command's logs and subject by command id.
type commandReader interface {
	ListForCommand(ctx context.Context, tenantID, commandID shared.ID, maxLines int) (Page, error)
	SubjectFinding(ctx context.Context, tenantID, commandID shared.ID) (*shared.ID, error)
}

// sanitize makes one line safe to store and show: bounded, plain, redacted.
// A timestamp that is missing, unreadable or in the future is the receive
// time.
func (s *Service) sanitize(raw RawLine, now time.Time) Line {
	l := Line{Level: level(raw.Level), Msg: s.text(raw.Msg, maxMsgBytes),
		Source: safetext.SingleLine(cut(raw.Source, maxSourceBytes), maxSourceBytes)}
	if ts, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(raw.TS)); err == nil && !ts.After(now.Add(time.Minute)) {
		l.TS = ts.UTC()
	} else {
		l.TS = now
	}
	if len(raw.Fields) == 0 {
		return l
	}
	keys := make([]string, 0, len(raw.Fields))
	for k := range raw.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic choice of the fields kept
	l.Fields = make(map[string]any, min(len(keys), maxFields))
	for _, k := range keys {
		if len(l.Fields) >= maxFields {
			break
		}
		key := safetext.SingleLine(cut(k, maxFieldKeyBytes), maxFieldKeyBytes)
		if key == "" {
			continue
		}
		l.Fields[key] = s.value(raw.Fields[k])
	}
	return l
}

// value flattens a field value to a bool, a number or a redacted string.
func (s *Service) value(raw json.RawMessage) any {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return ""
	}
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x
	case string:
		return s.text(x, maxFieldValBytes)
	case nil:
		return ""
	default: // objects and arrays: their JSON text
		return s.text(string(raw), maxFieldValBytes)
	}
}

// text cleans, redacts and caps s (redaction runs before the cap, so a cut
// cannot split a secret past the pattern).
func (s *Service) text(v string, maxBytes int) string {
	v = s.redactor.RedactString(safetext.Clean(cut(v, 4*maxBytes)))
	return cut(v, maxBytes)
}

func level(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case LevelDebug:
		return LevelDebug
	case LevelWarn, "warning":
		return LevelWarn
	case LevelError:
		return LevelError
	default:
		return LevelInfo
	}
}

// cut caps s at n bytes on a rune boundary.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
