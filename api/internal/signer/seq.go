package signer

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// SeqStore hands out a strictly increasing sequence number per sensor. Each
// number is written and fsync'd to the sensor's file under dir before it is
// returned, so a crash can lose numbers (a gap, which verifiers allow) but
// never hand one out twice.
type SeqStore struct {
	dir  string
	mu   sync.Mutex
	last map[string]uint64
}

// OpenSeqStore opens (creating it 0700) the sequence directory.
func OpenSeqStore(dir string) (*SeqStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("signer seq store: %w", err)
	}
	return &SeqStore{dir: dir, last: map[string]uint64{}}, nil
}

// Next is sensorID's next sequence number (1 for a sensor never seen).
// sensorID must already be a validated UUID: it names the file.
func (s *SeqStore) Next(sensorID string) (uint64, error) {
	if !isUUID(sensorID) {
		return 0, errors.New("signer seq store: invalid sensor id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.last[sensorID]
	if !ok {
		var err error
		if cur, err = s.read(sensorID); err != nil {
			return 0, err
		}
	}
	if cur == math.MaxUint64 {
		return 0, errors.New("signer seq store: sequence exhausted")
	}
	next := cur + 1
	if err := s.write(sensorID, next); err != nil {
		// The number may or may not be on disk: forget the cache so the
		// next call re-reads what is there.
		delete(s.last, sensorID)
		return 0, err
	}
	s.last[sensorID] = next
	return next, nil
}

func (s *SeqStore) path(sensorID string) string { return filepath.Join(s.dir, sensorID) }

func (s *SeqStore) read(sensorID string) (uint64, error) {
	raw, err := os.ReadFile(s.path(sensorID))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("signer seq store: %w", err)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		// A corrupt file must not restart the sequence at 1.
		return 0, fmt.Errorf("signer seq store: corrupt sequence file for %s", sensorID)
	}
	return n, nil
}

// write replaces the sensor's file atomically: a temporary file, fsync,
// rename, then fsync of the directory.
func (s *SeqStore) write(sensorID string, n uint64) error {
	tmp, err := os.CreateTemp(s.dir, "."+sensorID+".*")
	if err != nil {
		return fmt.Errorf("signer seq store: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() // no-op after the rename
	if _, err := tmp.WriteString(strconv.FormatUint(n, 10) + "\n"); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("signer seq store: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("signer seq store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("signer seq store: %w", err)
	}
	if err := os.Rename(name, s.path(sensorID)); err != nil {
		return fmt.Errorf("signer seq store: %w", err)
	}
	return syncDir(s.dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- the signer's own state directory
	if err != nil {
		return fmt.Errorf("signer: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("signer: %w", err)
	}
	return nil
}

// isUUID reports whether s is a canonical lower-case UUID (one spelling per
// id: an upper-case variant would start a second sequence).
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}
