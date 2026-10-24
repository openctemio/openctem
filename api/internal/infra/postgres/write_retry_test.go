package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/lib/pq"
)

// A deadlock or serialization failure runs the write again, at most
// writeConflictAttempts times in all; any other error returns at once.
func TestRetryWriteConflict(t *testing.T) {
	ctx := context.Background()
	for _, conflict := range []*pq.Error{{Code: deadlockDetected}, {Code: serializationFailure}} {
		calls := 0
		err := retryWriteConflict(ctx, func() error {
			calls++
			if calls < 3 {
				return conflict
			}
			return nil
		})
		if err != nil || calls != 3 {
			t.Fatalf("%s: err %v after %d calls, want success on the third", conflict.Code, err, calls)
		}
		calls = 0
		err = retryWriteConflict(ctx, func() error { calls++; return conflict })
		if !isWriteConflict(err) || calls != writeConflictAttempts {
			t.Fatalf("%s: err %v after %d calls, want the conflict after %d", conflict.Code, err, calls, writeConflictAttempts)
		}
	}
	calls := 0
	other := &pq.Error{Code: "23505"}
	if err := retryWriteConflict(ctx, func() error { calls++; return other }); !errors.Is(err, other) || calls != 1 {
		t.Fatalf("a unique violation was retried: %d calls", calls)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	calls = 0
	if err := retryWriteConflict(canceled, func() error { calls++; return &pq.Error{Code: deadlockDetected} }); err == nil || calls != 1 {
		t.Fatalf("a canceled context kept retrying: %d calls", calls)
	}
	if w := writeConflictWait(3); w < 2*writeConflictBaseWait || w >= 6*writeConflictBaseWait {
		t.Fatalf("third back-off %v outside [2, 6) x base", w)
	}
}
