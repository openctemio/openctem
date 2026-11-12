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

type fakeBytes struct {
	n   int64
	err error
}

func (f fakeBytes) TenantQueuedBytes(context.Context, shared.ID) (int64, error) { return f.n, f.err }

func TestAdmitBytes(t *testing.T) {
	ctx, now, tenant := context.Background(), time.Now(), shared.NewID()
	depth := fakeDepth{finished: 60}
	// Within the ceiling, exactly at it.
	if err := AdmitBytes(ctx, depth, fakeBytes{n: 900}, tenant, 100, 1000, now); err != nil {
		t.Fatalf("at the ceiling: %v", err)
	}
	// Over it: queue-full with a Retry-After from the drain rate.
	err := AdmitBytes(ctx, depth, fakeBytes{n: 901}, tenant, 100, 1000, now)
	var full *ErrQueueFull
	if !errors.As(err, &full) || full.RetryAfter != minRetryAfter {
		t.Fatalf("over the ceiling: %v", err)
	}
	// One segment bigger than the whole ceiling can never fit.
	if err := AdmitBytes(ctx, depth, fakeBytes{}, tenant, 1001, 1000, now); !errors.As(err, &full) {
		t.Fatalf("incoming over the ceiling: %v", err)
	}
	// Unreadable bytes or depth refuse (fail closed); no reader refuses.
	if err := AdmitBytes(ctx, depth, fakeBytes{err: errors.New("db down")}, tenant, 1, 1000, now); !errors.Is(err, ErrDepthUnknown) {
		t.Fatalf("bytes error: %v", err)
	}
	if err := AdmitBytes(ctx, fakeDepth{err: errors.New("db down")}, fakeBytes{n: 5000}, tenant, 1, 1000, now); !errors.Is(err, ErrDepthUnknown) {
		t.Fatalf("depth error: %v", err)
	}
	if err := AdmitBytes(ctx, depth, nil, tenant, 1, 1000, now); !errors.Is(err, ErrDepthUnknown) {
		t.Fatalf("no reader: %v", err)
	}
	// Disabled.
	if err := AdmitBytes(ctx, nil, nil, tenant, 1<<40, 0, now); err != nil {
		t.Fatalf("limit 0: %v", err)
	}
}
