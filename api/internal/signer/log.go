package signer

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Decisions recorded in the signing log.
const (
	DecisionSigned  = "signed"
	DecisionRefused = "refused"
)

// GenesisHash is the prev of the first log entry.
var GenesisHash = "sha256:" + strings.Repeat("0", 64)

// maxLogLine bounds one log line when the log is read back.
const maxLogLine = 64 << 10

// LogEntry is one line of the signing log. Prev is the hash of the previous
// line's bytes (without its newline), so removing, reordering or editing a
// line breaks the chain from there on.
type LogEntry struct {
	Time            time.Time `json:"time"`
	Decision        string    `json:"decision"`
	Reason          string    `json:"reason,omitempty"`
	TenantID        string    `json:"tenant_id,omitempty"`
	SensorID        string    `json:"sensor_id,omitempty"`
	CommandID       string    `json:"command_id,omitempty"`
	CommandType     string    `json:"command_type,omitempty"`
	Tool            string    `json:"tool,omitempty"`
	PayloadSHA256   string    `json:"payload_sha256,omitempty"`
	Targets         int       `json:"targets,omitempty"`
	Seq             uint64    `json:"seq,omitempty"`
	KeyID           string    `json:"keyid,omitempty"`
	StatementSHA256 string    `json:"statement_sha256,omitempty"`
	// LedgerAudit is the ledger refusal a signature was given despite
	// (SIGNER_LEDGER=audit): what enforce mode would have refused.
	LedgerAudit string `json:"ledger_audit,omitempty"`
	Prev        string `json:"prev"`
}

// SigningLog is the signer's append-only, hash-chained JSONL record of every
// signature and refusal. Each line is fsync'd before the decision is
// answered.
type SigningLog struct {
	mu   sync.Mutex
	f    *os.File
	prev string
	// broken is set after a failed write: the file may end in a torn line,
	// so nothing more is appended (and nothing more signed) until restart
	// verifies it.
	broken bool
	// entries is the number of lines the log held when it was opened.
	entries int
}

// OpenSigningLog opens (creating it 0600) the log at path and verifies the
// chain already in it. A log whose chain is broken, or whose last line is
// torn, is refused: the operator inspects it (openctem-signer verify-log)
// before the signer signs again.
func OpenSigningLog(path string) (*SigningLog, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600) // #nosec G304 -- the signer's own state file
	if err != nil {
		return nil, fmt.Errorf("signing log: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("signing log: %w", err)
	}
	last, n, err := VerifyLog(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &SigningLog{f: f, prev: last, entries: n}, nil
}

// Append writes e (its Prev set here) and fsyncs it.
func (l *SigningLog) Append(e LogEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.broken {
		return errors.New("signing log: an earlier write failed; restart the signer")
	}
	e.Time = e.Time.UTC()
	e.Prev = l.prev
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("signing log: %w", err)
	}
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("signing log: %w", err)
	}
	l.prev = lineHash(line)
	return nil
}

// Close closes the log.
func (l *SigningLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

// VerifyLog reads a signing log and checks every link. It returns the hash
// of the last line (GenesisHash for an empty log) and the number of lines.
func VerifyLog(r io.Reader) (last string, n int, err error) {
	last = GenesisHash
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, rerr := br.ReadBytes('\n')
		if len(line) > 0 {
			if line[len(line)-1] != '\n' {
				return "", n, fmt.Errorf("signing log: line %d is torn (no newline)", n+1)
			}
			line = bytes.TrimSuffix(line, []byte("\n"))
			if len(line) > maxLogLine {
				return "", n, fmt.Errorf("signing log: line %d is too long", n+1)
			}
			var e LogEntry
			if err := json.Unmarshal(line, &e); err != nil {
				return "", n, fmt.Errorf("signing log: line %d: %w", n+1, err)
			}
			if e.Prev != last {
				return "", n, fmt.Errorf("signing log: chain broken at line %d", n+1)
			}
			last = lineHash(line)
			n++
		}
		if errors.Is(rerr, io.EOF) {
			return last, n, nil
		}
		if rerr != nil {
			return "", n, fmt.Errorf("signing log: %w", rerr)
		}
	}
}

func lineHash(line []byte) string {
	sum := sha256.Sum256(line)
	return "sha256:" + hex.EncodeToString(sum[:])
}
