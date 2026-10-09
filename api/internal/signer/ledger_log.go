package signer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// maxLedgerLine bounds one ledger.log line: an import record carries one
// organization's whole ledger.
const maxLedgerLine = 32 << 20

// chainLog is ledger.log: append-only JSONL whose every line carries prev,
// the hash of the line before it (GenesisHash for the first), fsync'd
// before the change it records takes effect. It is the signing log's
// format with a larger line bound.
type chainLog struct {
	mu      sync.Mutex
	f       *os.File
	name    string
	prev    string
	entries int
	broken  bool
}

// openChainLog opens (creating it 0600) the log at path, verifies its
// chain and hands each line to replay in order. A broken chain, a torn last
// line or a line replay refuses stops the open.
func openChainLog(path, name string, maxLine int, replay func(line []byte) error) (*chainLog, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600) // #nosec G304 -- the signer's own state file
	if err != nil {
		return nil, fmt.Errorf("%s log: %w", name, err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%s log: %w", name, err)
	}
	last, n, err := verifyChain(f, name, maxLine, replay)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &chainLog{f: f, name: name, prev: last, entries: n}, nil
}

// verifyChain reads a chained log, checks every link and hands each line to
// replay (nil: none). It returns the hash of the last line and the number of
// lines.
func verifyChain(r io.Reader, name string, maxLine int, replay func(line []byte) error) (last string, n int, err error) {
	last = GenesisHash
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, rerr := readLine(br, maxLine)
		if len(line) > 0 {
			if line[len(line)-1] != '\n' {
				return "", n, fmt.Errorf("%s log: line %d is torn or too long", name, n+1)
			}
			line = bytes.TrimSuffix(line, []byte("\n"))
			var link struct {
				Prev string `json:"prev"`
			}
			if err := json.Unmarshal(line, &link); err != nil {
				return "", n, fmt.Errorf("%s log: line %d: %w", name, n+1, err)
			}
			if link.Prev != last {
				return "", n, fmt.Errorf("%s log: chain broken at line %d", name, n+1)
			}
			if replay != nil {
				if err := replay(line); err != nil {
					return "", n, fmt.Errorf("%s log: line %d: %w", name, n+1, err)
				}
			}
			last = lineHash(line)
			n++
		}
		if errors.Is(rerr, io.EOF) {
			return last, n, nil
		}
		if rerr != nil {
			return "", n, fmt.Errorf("%s log: %w", name, rerr)
		}
	}
}

// readLine reads up to and including '\n', at most maxLine+1 bytes: a
// longer line comes back without its newline (and is refused as torn).
func readLine(br *bufio.Reader, maxLine int) ([]byte, error) {
	var out []byte
	for {
		chunk, err := br.ReadSlice('\n')
		out = append(out, chunk...)
		if len(out) > maxLine+1 {
			return out[:maxLine+1], nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return out, err
	}
}

// append writes r (its Prev set here) and fsyncs it.
func (l *chainLog) append(r *LedgerRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.broken {
		return fmt.Errorf("%s log: an earlier write failed; restart the signer", l.name)
	}
	r.Prev = l.prev
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(line) > maxLedgerLine {
		return fmt.Errorf("%s log: record of %d bytes is over %d", l.name, len(line), maxLedgerLine)
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		l.broken = true
		return fmt.Errorf("%s log: %w", l.name, err)
	}
	if err := l.f.Sync(); err != nil {
		l.broken = true
		return fmt.Errorf("%s log: %w", l.name, err)
	}
	l.prev = lineHash(line)
	l.entries++
	return nil
}

func (l *chainLog) close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

// strictUnmarshal decodes one JSON value refusing unknown fields.
func strictUnmarshal(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// VerifyLedgerLog checks a ledger.log's chain and that every record
// replays, without taking the lock. It returns the last hash and the number
// of records.
func VerifyLedgerLog(r io.Reader) (string, int, error) {
	l := &Ledger{tenants: map[string]*tenantLedger{}}
	return verifyChain(r, "ledger", maxLedgerLine, func(line []byte) error {
		var rec LedgerRecord
		if err := strictUnmarshal(line, &rec); err != nil {
			return err
		}
		return l.replay(rec)
	})
}
