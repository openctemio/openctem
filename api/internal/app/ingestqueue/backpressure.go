package ingestqueue

// Back-pressure at accept (docs/rfcs/RFC-122-ingest-receipts.md, "Fairness
// and limits"): a tenant whose queue holds its limit of unfinished jobs is
// answered 429 with a Retry-After computed from how fast its jobs drain; a
// queue depth that cannot be read refuses the upload (fail closed), it never
// waves it through.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// DepthReader reads a tenant's queue depth and recent drain.
type DepthReader interface {
	// TenantDepth counts the tenant's unfinished jobs (pending or
	// processing) and the jobs it finished since the given time.
	TenantDepth(ctx context.Context, tenantID shared.ID, finishedSince time.Time) (unfinished, finished int, err error)
}

// ErrQueueFull is a tenant at its queue limit; RetryAfter says when to try
// again.
type ErrQueueFull struct {
	RetryAfter time.Duration
}

func (e *ErrQueueFull) Error() string {
	return fmt.Sprintf("the ingest queue of this organization is full; retry after %s", e.RetryAfter)
}

// ErrDepthUnknown: the queue depth could not be read; the upload is refused.
var ErrDepthUnknown = errors.New("the ingest queue depth could not be read")

// Retry-After bounds.
const (
	minRetryAfter = 5 * time.Second
	maxRetryAfter = 5 * time.Minute
	drainWindow   = 5 * time.Minute
)

// Admit checks a tenant's queue depth before an upload is stored. limit <= 0
// disables the check.
func Admit(ctx context.Context, depth DepthReader, tenantID shared.ID, limit int, now time.Time) error {
	if limit <= 0 {
		return nil
	}
	if depth == nil {
		return ErrDepthUnknown
	}
	unfinished, finished, err := depth.TenantDepth(ctx, tenantID, now.Add(-drainWindow))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDepthUnknown, err)
	}
	if unfinished < limit {
		return nil
	}
	return &ErrQueueFull{RetryAfter: retryAfter(unfinished-limit+1, finished)}
}

// BytesReader reads the bytes a tenant has queued.
type BytesReader interface {
	// TenantQueuedBytes is the decoded size of the payloads of the tenant's
	// unfinished sensor jobs (ingest_jobs.payload_bytes).
	TenantQueuedBytes(ctx context.Context, tenantID shared.ID) (int64, error)
}

// AdmitBytes checks, before a payload of incoming bytes is stored, that the
// tenant's queued bytes plus it stay within limit: a tenant over it is
// answered like one at its job limit (ErrQueueFull, Retry-After from its
// recent drain), so the byte ceiling and the job ceiling look the same to a
// sender. limit <= 0 disables the check; bytes that cannot be read refuse
// the payload (fail closed).
func AdmitBytes(ctx context.Context, depth DepthReader, queued BytesReader, tenantID shared.ID,
	incoming, limit int64, now time.Time,
) error {
	if limit <= 0 {
		return nil
	}
	if queued == nil || depth == nil {
		return ErrDepthUnknown
	}
	n, err := queued.TenantQueuedBytes(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDepthUnknown, err)
	}
	if n+incoming <= limit {
		return nil
	}
	_, finished, err := depth.TenantDepth(ctx, tenantID, now.Add(-drainWindow))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDepthUnknown, err)
	}
	return &ErrQueueFull{RetryAfter: retryAfter(1, finished)}
}

// retryAfter is how long until `over` jobs drained at the tenant's recent
// rate (finished jobs in the drain window), bounded.
func retryAfter(over, finished int) time.Duration {
	if finished <= 0 {
		return maxRetryAfter / 5
	}
	per := drainWindow / time.Duration(finished)
	d := per * time.Duration(over)
	return max(minRetryAfter, min(d, maxRetryAfter))
}
