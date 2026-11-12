package controller

// Retention of ingest receipts (docs/rfcs/RFC-122-ingest-receipts.md): action
// rows after 90 days, run receipts and daily ingest facts after 400 days.
// Upload receipts stay: each is the producer record of the findings and
// assets its upload wrote.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
)

// IngestReceiptRetentionInterval is how often the purge runs.
const IngestReceiptRetentionInterval = time.Hour

// ingestReceiptPurgeBatch and ingestReceiptPurgeMaxBatches bound one pass:
// short statements, at most 100,000 rows of each kind per hour.
const (
	ingestReceiptPurgeBatch      = 5000
	ingestReceiptPurgeMaxBatches = 20
)

// IngestReceiptRetentionStore deletes old receipt data
// (postgres.IngestReceiptRepository).
type IngestReceiptRetentionStore interface {
	PurgeActionsForPlatform(ctx context.Context, before time.Time, limit int) (int64, error)
	PurgeRunReceiptsForPlatform(ctx context.Context, before time.Time, limit int) (int64, error)
	PurgeFactsForPlatform(ctx context.Context, before time.Time, limit int) (int64, error)
}

// IdempotencyKeyPurger deletes expired Idempotency-Key records
// (postgres.IdempotencyKeyRepository).
type IdempotencyKeyPurger interface {
	PurgeExpiredForPlatform(ctx context.Context, before time.Time, limit int) (int64, error)
}

// IngestReceiptRetentionController purges on one replica at a time.
type IngestReceiptRetentionController struct {
	store    IngestReceiptRetentionStore
	keys     IdempotencyKeyPurger
	interval time.Duration
	now      func() time.Time
}

// NewIngestReceiptRetentionController creates the controller; interval <= 0
// uses IngestReceiptRetentionInterval.
func NewIngestReceiptRetentionController(store IngestReceiptRetentionStore, interval time.Duration) *IngestReceiptRetentionController {
	if interval <= 0 {
		interval = IngestReceiptRetentionInterval
	}
	return &IngestReceiptRetentionController{store: store, interval: interval, now: time.Now}
}

// WithIdempotencyKeys also purges expired Idempotency-Key records.
func (c *IngestReceiptRetentionController) WithIdempotencyKeys(keys IdempotencyKeyPurger) {
	c.keys = keys
}

// Name implements Controller.
func (c *IngestReceiptRetentionController) Name() string { return "ingest-receipt-retention" }

// Interval implements Controller.
func (c *IngestReceiptRetentionController) Interval() time.Duration { return c.interval }

// Exclusive implements Exclusive: one replica purges.
func (c *IngestReceiptRetentionController) Exclusive() bool { return true }

// Reconcile implements Controller: returns the rows deleted.
func (c *IngestReceiptRetentionController) Reconcile(ctx context.Context) (int, error) {
	now := c.now().UTC()
	total := int64(0)
	type step struct {
		purge  func(context.Context, time.Time, int) (int64, error)
		before time.Time
	}
	steps := []step{
		{c.store.PurgeActionsForPlatform, now.Add(-ingestreceipt.ActionRetention)},
		{c.store.PurgeRunReceiptsForPlatform, now.Add(-ingestreceipt.RunReceiptRetention)},
		{c.store.PurgeFactsForPlatform, now.Add(-ingestreceipt.FactRetention)},
	}
	if c.keys != nil {
		steps = append(steps, step{c.keys.PurgeExpiredForPlatform, now})
	}
	for _, step := range steps {
		for range ingestReceiptPurgeMaxBatches {
			if err := ctx.Err(); err != nil {
				return int(total), err
			}
			n, err := step.purge(ctx, step.before, ingestReceiptPurgeBatch)
			if err != nil {
				return int(total), err
			}
			total += n
			if n < ingestReceiptPurgeBatch {
				break
			}
		}
	}
	return int(total), nil
}
