package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/logger"
)

// PriorityReclassifySweepController is the periodic *producer* half of the
// priority-reclassification pipeline. PriorityReclassifyController is the
// consumer — it drains the queue but nothing periodically fills it, so
// findings that no discrete producer event touches (never-classified rows
// with priority_class IS NULL, or slow daily EPSS drift) would never be
// reclassified.
//
// This controller closes that gap: on an interval it lists every active
// tenant and enqueues ONE whole-tenant ReclassifyRequest per tenant (empty
// AssetIDs → the Reclassifier expands it to the tenant's open findings'
// distinct assets). The consumer then does the work at its own cadence.
//
// Producer and consumer are deliberately separate controllers: the producer
// only enqueues (cheap, fast) and the consumer drains in bounded batches, so
// a slow reclassify never blocks enqueue and vice-versa.
//
// Interval is intentionally low-frequency (default 12h): this is drift
// correction + backfill, not real-time. Real-time transitions already flow
// through the discrete producers (control-change, KEV/EPSS refresh). A high
// frequency would re-classify the whole corpus constantly for no benefit.
type PriorityReclassifySweepController struct {
	queue      ReclassifyQueue
	tenantRepo tenant.Repository
	config     *PriorityReclassifySweepConfig
	logger     *logger.Logger
}

// PriorityReclassifySweepConfig configures the periodic sweep producer.
type PriorityReclassifySweepConfig struct {
	// Interval between sweeps. Default 12h. Backfill + drift correction, so a
	// low frequency is deliberate.
	Interval time.Duration
	// Logger (optional; defaults to no-op).
	Logger *logger.Logger
}

// NewPriorityReclassifySweepController wires the producer. A nil queue makes
// Reconcile a no-op (the whole pipeline is optional in some deployments).
func NewPriorityReclassifySweepController(
	queue ReclassifyQueue,
	tenantRepo tenant.Repository,
	cfg *PriorityReclassifySweepConfig,
) *PriorityReclassifySweepController {
	if cfg == nil {
		cfg = &PriorityReclassifySweepConfig{}
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 12 * time.Hour
	}
	if cfg.Logger == nil {
		cfg.Logger = logger.NewNop()
	}
	return &PriorityReclassifySweepController{
		queue:      queue,
		tenantRepo: tenantRepo,
		config:     cfg,
		logger:     cfg.Logger.With("controller", "priority-reclassify-sweep"),
	}
}

// Name returns the controller name.
func (c *PriorityReclassifySweepController) Name() string { return "priority-reclassify-sweep" }

// Interval returns the sweep interval.
func (c *PriorityReclassifySweepController) Interval() time.Duration { return c.config.Interval }

// Reconcile enqueues one whole-tenant ReclassifyRequest per active tenant.
// Returns the number of tenants enqueued. Best-effort: a failed enqueue for
// one tenant is logged and does not stop the rest. Only an unrecoverable
// tenant-list failure is returned (so the runner retries next tick).
func (c *PriorityReclassifySweepController) Reconcile(ctx context.Context) (int, error) {
	if c.queue == nil {
		return 0, nil
	}

	tenantIDs, err := c.tenantRepo.ListActiveTenantIDs(ctx)
	if err != nil {
		return 0, err
	}

	enqueued := 0
	for _, tid := range tenantIDs {
		if ctx.Err() != nil {
			return enqueued, ctx.Err()
		}
		req := ReclassifyRequest{
			TenantID:  tid,
			Reason:    ReasonPeriodicSweep,
			EnqueueAt: time.Now().UTC(),
		}
		if err := c.queue.Enqueue(ctx, req); err != nil {
			c.logger.Warn("enqueue periodic reclassify sweep failed; continuing with next tenant",
				"tenant_id", tid.String(),
				"error", err,
			)
			continue
		}
		enqueued++
	}
	c.logger.Debug("priority reclassify sweep enqueued",
		"tenants_total", len(tenantIDs),
		"tenants_enqueued", enqueued,
	)
	return enqueued, nil
}
