package postgres

// Bounded retry of a write that lost a lock conflict to a concurrent writer
// (docs/architecture/deduplication.md, "Concurrent uploads").
//
// Concurrent uploads of one repository or one tenant write the same rows.
// The batched writes take their row locks in one order (sorted by id or
// fingerprint), so they queue instead of deadlocking; a deadlock that still
// happens (a trigger, another code path) or a serialization failure rolls
// back only the losing statement or transaction, which is safe to run again.
// Retrying it, instead of falling back to a slower path or dropping the
// sightings, keeps every reported finding recorded.

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"

	"github.com/lib/pq"
)

// serializationFailure is PostgreSQL's SQLSTATE for a serialization failure
// (deadlockDetected, 40P01, is declared with retryOnDeadlock).
const serializationFailure = "40001"

// writeConflictAttempts bounds the runs of one write (the first run and the
// retries).
const writeConflictAttempts = 5

// writeConflictBaseWait is the first back-off; each retry doubles it, with
// jitter so the writers that collided do not collide again.
const writeConflictBaseWait = 20 * time.Millisecond

// isWriteConflict reports whether err is a deadlock or a serialization
// failure: the database rolled the work back and it may run again.
func isWriteConflict(err error) bool {
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) {
		return false
	}
	switch string(pqErr.Code) {
	case deadlockDetected, serializationFailure:
		return true
	}
	return false
}

// retryWriteConflict runs fn, and again (at most writeConflictAttempts runs
// in all) while it fails with a write conflict, after a jittered exponential
// back-off. fn must be a whole statement or transaction, so a run that
// failed left nothing behind. Any other error, or the context ending,
// returns at once.
func retryWriteConflict(ctx context.Context, fn func() error) error {
	var err error
	for attempt := 0; attempt < writeConflictAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return err
			case <-time.After(writeConflictWait(attempt)):
			}
		}
		if err = fn(); err == nil || !isWriteConflict(err) {
			return err
		}
	}
	return err
}

// writeConflictWait is the back-off before retry number attempt (1-based):
// base * 2^(attempt-1), scaled by a random factor in [0.5, 1.5).
func writeConflictWait(attempt int) time.Duration {
	wait := writeConflictBaseWait << (attempt - 1)
	var b [2]byte
	_, _ = rand.Read(b[:]) // jitter only; zero on error is fine
	frac := float64(binary.LittleEndian.Uint16(b[:])) / 65536.0
	return time.Duration(float64(wait) * (0.5 + frac))
}
