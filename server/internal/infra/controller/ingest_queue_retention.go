package controller

// Retention of the ingest queue (docs/rfcs/RFC-122-ingest-receipts.md,
// "Queue hygiene"): finished jobs and protocol v2 reports after 30 days, and
// stored upload parts as soon as nobody will open them (applied, expired, or
// staged by an upload that never got a job). Receipts keep what each upload
// did.

import (
	"context"
	"time"
)

// IngestQueueRetentionInterval is how often the purge runs.
const IngestQueueRetentionInterval = time.Hour

// IngestQueueRetention is how long finished jobs and reports are kept.
const IngestQueueRetention = 30 * 24 * time.Hour

const (
	ingestQueuePurgeBatch      = 5000
	ingestQueuePurgeMaxBatches = 20
)

// IngestQueueRetentionStore deletes finished queue rows
// (postgres.IngestJobRepository).
type IngestQueueRetentionStore interface {
	PurgePayloadsForPlatform(ctx context.Context, now time.Time, limit int) (int64, error)
	PurgeFinishedJobsForPlatform(ctx context.Context, before time.Time, limit int) (int64, error)
	PurgeFinishedReportsForPlatform(ctx context.Context, before time.Time, limit int) (int64, error)
}

// IngestQueueRetentionController purges on one replica at a time.
type IngestQueueRetentionController struct {
	store    IngestQueueRetentionStore
	interval time.Duration
	now      func() time.Time
}

// NewIngestQueueRetentionController creates the controller; interval <= 0
// uses IngestQueueRetentionInterval.
func NewIngestQueueRetentionController(store IngestQueueRetentionStore, interval time.Duration) *IngestQueueRetentionController {
	if interval <= 0 {
		interval = IngestQueueRetentionInterval
	}
	return &IngestQueueRetentionController{store: store, interval: interval, now: time.Now}
}

// Name implements Controller.
func (c *IngestQueueRetentionController) Name() string { return "ingest-queue-retention" }

// Interval implements Controller.
func (c *IngestQueueRetentionController) Interval() time.Duration { return c.interval }

// Exclusive implements Exclusive: one replica purges.
func (c *IngestQueueRetentionController) Exclusive() bool { return true }

// Reconcile implements Controller: returns the rows deleted. Each kind runs
// in short batches, at most ingestQueuePurgeMaxBatches per pass.
func (c *IngestQueueRetentionController) Reconcile(ctx context.Context) (int, error) {
	now := c.now().UTC()
	cutoff := now.Add(-IngestQueueRetention)
	steps := []func(context.Context, int) (int64, error){
		func(ctx context.Context, n int) (int64, error) { return c.store.PurgePayloadsForPlatform(ctx, now, n) },
		func(ctx context.Context, n int) (int64, error) {
			return c.store.PurgeFinishedJobsForPlatform(ctx, cutoff, n)
		},
		func(ctx context.Context, n int) (int64, error) {
			return c.store.PurgeFinishedReportsForPlatform(ctx, cutoff, n)
		},
	}
	total := int64(0)
	for _, purge := range steps {
		for range ingestQueuePurgeMaxBatches {
			n, err := purge(ctx, ingestQueuePurgeBatch)
			if err != nil {
				return int(total), err
			}
			total += n
			if n < ingestQueuePurgeBatch {
				break
			}
		}
	}
	return int(total), nil
}
