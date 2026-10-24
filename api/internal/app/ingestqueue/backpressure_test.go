package ingestqueue

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeDepth struct {
	unfinished, finished int
	err                  error
}

func (f fakeDepth) TenantDepth(context.Context, shared.ID, time.Time) (int, int, error) {
	return f.unfinished, f.finished, f.err
}

func TestAdmit(t *testing.T) {
	now := time.Now()
	tenant := shared.NewID()
	if err := Admit(context.Background(), fakeDepth{unfinished: 99}, tenant, 100, now); err != nil {
		t.Fatalf("under the limit: %v", err)
	}
	// A depth that cannot be read refuses (fail closed).
	if err := Admit(context.Background(), fakeDepth{err: errors.New("db down")}, tenant, 100, now); !errors.Is(err, ErrDepthUnknown) {
		t.Fatalf("depth error: %v", err)
	}
	if err := Admit(context.Background(), nil, tenant, 100, now); !errors.Is(err, ErrDepthUnknown) {
		t.Fatalf("no reader: %v", err)
	}
	// At the limit: 429 with a Retry-After from the drain rate.
	err := Admit(context.Background(), fakeDepth{unfinished: 100, finished: 60}, tenant, 100, now)
	var full *ErrQueueFull
	if !errors.As(err, &full) || full.RetryAfter != minRetryAfter {
		t.Fatalf("full, fast drain: %v", err)
	}
	err = Admit(context.Background(), fakeDepth{unfinished: 130, finished: 10}, tenant, 100, now)
	if !errors.As(err, &full) || full.RetryAfter != maxRetryAfter {
		t.Fatalf("full, slow drain: %v (%v)", err, full)
	}
	err = Admit(context.Background(), fakeDepth{unfinished: 100}, tenant, 100, now)
	if !errors.As(err, &full) || full.RetryAfter <= 0 {
		t.Fatalf("full, nothing drained: %v", err)
	}
	// Disabled.
	if err := Admit(context.Background(), nil, tenant, 0, now); err != nil {
		t.Fatalf("limit 0: %v", err)
	}
}
