package controller

// Dashboard facts upkeep (docs/architecture/dashboards.md, "Facts
// maintainer"). Two leased controllers, so a long rebuild never delays the
// change queue:
//
//   - dashboard-facts (every 30 s): drains the dirty-asset queue, tenants in
//     round-robin with a time slice each, so one busy tenant cannot starve
//     the others. Each claim recomputes the marked assets and deletes exactly
//     the claimed rows in one transaction.
//   - dashboard-facts-reconcile (every minute): full runs, resumable across
//     ticks (first build of a tenant, a requested "Rebuild dashboard data",
//     the nightly reconciliation that counts drift), the daily age-band
//     marking, and the F2 partitions (create ahead, drop past the 13-month
//     window).

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/dashboardfact"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// DashboardFactQueueStore is the storage of the queue controller
// (*postgres.DashboardFactsRepository).
type DashboardFactQueueStore interface {
	TenantsWithDirtyForPlatform(ctx context.Context, limit int) ([]shared.ID, error)
	ProcessDirty(ctx context.Context, tenantID shared.ID, limit int) (dashboardfact.DirtyBatch, error)
	QueueStatsForPlatform(ctx context.Context) (int, time.Time, error)
}

const (
	dashboardFactsInterval   = 30 * time.Second
	dashboardFactsBudget     = 25 * time.Second
	dashboardFactsSlice      = 5 * time.Second
	dashboardFactsClaim      = 500
	dashboardFactsMaxTenants = 10000
)

// DashboardFactsController drains the dashboard fact change queue.
type DashboardFactsController struct {
	store  DashboardFactQueueStore
	claim  int
	budget time.Duration
	slice  time.Duration
	// last is the tenant served last; the next tick starts after it.
	last   shared.ID
	now    func() time.Time
	logger *logger.Logger
}

// NewDashboardFactsController creates the queue controller.
func NewDashboardFactsController(store DashboardFactQueueStore, log *logger.Logger) *DashboardFactsController {
	if log == nil {
		log = logger.NewNop()
	}
	return &DashboardFactsController{
		store: store, claim: dashboardFactsClaim, budget: dashboardFactsBudget, slice: dashboardFactsSlice,
		now: time.Now, logger: log,
	}
}

// Name returns the controller name.
func (c *DashboardFactsController) Name() string { return "dashboard-facts" }

// Interval returns the reconciliation interval.
func (c *DashboardFactsController) Interval() time.Duration { return dashboardFactsInterval }

// Exclusive: one replica drains the queue at a time.
func (c *DashboardFactsController) Exclusive() bool { return true }

// Reconcile drains the queue within the tick budget and returns the number
// of change marks processed.
func (c *DashboardFactsController) Reconcile(ctx context.Context) (int, error) {
	defer c.publishQueueStats(ctx)
	tenants, err := c.store.TenantsWithDirtyForPlatform(ctx, dashboardFactsMaxTenants)
	if err != nil {
		return 0, err
	}
	deadline := c.now().Add(c.budget)
	processed := 0
	for _, tid := range rotateAfter(tenants, c.last) {
		if ctx.Err() != nil || !c.now().Before(deadline) {
			break
		}
		n, err := c.drainTenant(ctx, tid, minTime(c.now().Add(c.slice), deadline))
		processed += n
		c.last = tid
		if err != nil {
			// One tenant's failure must not stop the others.
			c.logger.Error("dashboard facts: processing changes failed", "tenant_id", tid.String(), "error", err)
		}
	}
	return processed, nil
}

// drainTenant claims batches of one tenant until its queue is empty or the
// slice ends.
func (c *DashboardFactsController) drainTenant(ctx context.Context, tid shared.ID, until time.Time) (int, error) {
	processed := 0
	for ctx.Err() == nil && c.now().Before(until) {
		b, err := c.store.ProcessDirty(ctx, tid, c.claim)
		if err != nil {
			return processed, err
		}
		if b.Claimed == 0 {
			return processed, nil
		}
		processed += b.Claimed
		if !b.OldestMarkedAt.IsZero() {
			metrics.DashboardFactLagSeconds.Observe(max(c.now().Sub(b.OldestMarkedAt).Seconds(), 0))
		}
		if b.Claimed < c.claim {
			return processed, nil
		}
	}
	return processed, nil
}

func (c *DashboardFactsController) publishQueueStats(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	depth, oldest, err := c.store.QueueStatsForPlatform(ctx)
	if err != nil {
		c.logger.Warn("dashboard facts: queue stats failed", "error", err)
		return
	}
	metrics.DashboardFactQueueDepth.Set(float64(depth))
	age := 0.0
	if !oldest.IsZero() {
		age = max(c.now().Sub(oldest).Seconds(), 0)
	}
	metrics.DashboardFactQueueOldestSeconds.Set(age)
}

// rotateAfter returns ids (sorted ascending) starting with the first id
// greater than last, wrapping around, so successive ticks serve tenants in
// round-robin.
func rotateAfter(ids []shared.ID, last shared.ID) []shared.ID {
	if last.IsZero() || len(ids) == 0 {
		return ids
	}
	ls := last.String()
	for i, id := range ids {
		if id.String() > ls {
			return append(append(make([]shared.ID, 0, len(ids)), ids[i:]...), ids[:i]...)
		}
	}
	return ids
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// DashboardFactRunStore is the storage of the reconcile controller
// (*postgres.DashboardFactsRepository).
type DashboardFactRunStore interface {
	PendingRunsForPlatform(ctx context.Context, nightlyEvery time.Duration, limit int) ([]dashboardfact.PendingRun, error)
	StartRun(ctx context.Context, tenantID shared.ID, kind dashboardfact.RunKind) (bool, error)
	RunStep(ctx context.Context, tenantID shared.ID, batchSize int) (dashboardfact.RunStep, error)
	AgedMarkingDueForPlatform(ctx context.Context, every time.Duration, limit int) ([]dashboardfact.AgedMarkingDue, error)
	MarkAgedAssets(ctx context.Context, tenantID shared.ID, since, until time.Time) (int, error)
	MaintainPartitionsForPlatform(ctx context.Context) (created, dropped, moved int, err error)
}

const (
	dashboardReconcileInterval = time.Minute
	dashboardReconcileTimeout  = 5 * time.Minute
	dashboardReconcileBudget   = 4 * time.Minute
	dashboardDaily             = 24 * time.Hour
	dashboardRunBatch          = 200
	dashboardPendingLimit      = 100
)

// DashboardFactReconcileController runs full runs, age-band marking and F2
// partition upkeep.
type DashboardFactReconcileController struct {
	store        DashboardFactRunStore
	batch        int
	budget       time.Duration
	nightlyEvery time.Duration
	lastMaintain time.Time
	now          func() time.Time
	logger       *logger.Logger
}

// NewDashboardFactReconcileController creates the reconcile controller.
func NewDashboardFactReconcileController(store DashboardFactRunStore, log *logger.Logger) *DashboardFactReconcileController {
	if log == nil {
		log = logger.NewNop()
	}
	return &DashboardFactReconcileController{
		store: store, batch: dashboardRunBatch, budget: dashboardReconcileBudget, nightlyEvery: dashboardDaily,
		now: time.Now, logger: log,
	}
}

// Name returns the controller name.
func (c *DashboardFactReconcileController) Name() string { return "dashboard-facts-reconcile" }

// Interval returns the reconciliation interval.
func (c *DashboardFactReconcileController) Interval() time.Duration {
	return dashboardReconcileInterval
}

// ReconcileTimeout lets one tick run a few minutes of a long rebuild.
func (c *DashboardFactReconcileController) ReconcileTimeout() time.Duration {
	return dashboardReconcileTimeout
}

// Exclusive: one replica at a time.
func (c *DashboardFactReconcileController) Exclusive() bool { return true }

// Reconcile keeps the partitions, marks crossed age bands, and advances the
// pending full runs within the tick budget. Returns the assets-steps done.
func (c *DashboardFactReconcileController) Reconcile(ctx context.Context) (int, error) {
	deadline := c.now().Add(c.budget)
	c.maintainPartitions(ctx)
	c.markAged(ctx)

	pending, err := c.store.PendingRunsForPlatform(ctx, c.nightlyEvery, dashboardPendingLimit)
	if err != nil {
		return 0, err
	}
	steps := 0
	for _, p := range pending {
		if ctx.Err() != nil || !c.now().Before(deadline) {
			break
		}
		n, err := c.advance(ctx, p, deadline)
		steps += n
		if err != nil {
			c.logger.Error("dashboard facts: full run failed", "tenant_id", p.TenantID.String(),
				"kind", string(p.Kind), "error", err)
		}
	}
	return steps, nil
}

// advance starts (when needed) and steps one tenant's run until it is done
// or the deadline passes; an unfinished run resumes on the next tick.
func (c *DashboardFactReconcileController) advance(ctx context.Context, p dashboardfact.PendingRun, deadline time.Time) (int, error) {
	if !p.InProgress {
		if _, err := c.store.StartRun(ctx, p.TenantID, p.Kind); err != nil {
			return 0, err
		}
	}
	steps := 0
	for ctx.Err() == nil && c.now().Before(deadline) {
		s, err := c.store.RunStep(ctx, p.TenantID, c.batch)
		if err != nil {
			return steps, err
		}
		steps++
		// A first build finds every fact missing: that is not drift.
		if s.Drift > 0 && s.Kind != dashboardfact.RunInitial {
			metrics.DashboardFactDriftRowsTotal.WithLabelValues(string(s.Kind)).Add(float64(s.Drift))
			c.logger.Warn("dashboard facts: drift corrected", "tenant_id", p.TenantID.String(),
				"kind", string(s.Kind), "rows", s.Drift)
		}
		if s.Done {
			metrics.DashboardFactRunsTotal.WithLabelValues(string(s.Kind)).Inc()
			return steps, nil
		}
	}
	return steps, ctx.Err()
}

func (c *DashboardFactReconcileController) maintainPartitions(ctx context.Context) {
	if !c.lastMaintain.IsZero() && c.now().Sub(c.lastMaintain) < dashboardDaily {
		return
	}
	created, dropped, moved, err := c.store.MaintainPartitionsForPlatform(ctx)
	if err != nil {
		c.logger.Error("dashboard facts: partition upkeep failed", "error", err)
		return
	}
	c.lastMaintain = c.now()
	if created+dropped+moved > 0 {
		c.logger.Info("dashboard facts: partitions", "created", created, "dropped", dropped, "rows_moved", moved)
	}
}

func (c *DashboardFactReconcileController) markAged(ctx context.Context) {
	due, err := c.store.AgedMarkingDueForPlatform(ctx, dashboardDaily, 1000)
	if err != nil {
		c.logger.Error("dashboard facts: age-band marking failed", "error", err)
		return
	}
	now := c.now()
	for _, d := range due {
		if ctx.Err() != nil {
			return
		}
		if _, err := c.store.MarkAgedAssets(ctx, d.TenantID, d.Since, now); err != nil {
			c.logger.Error("dashboard facts: age-band marking failed", "tenant_id", d.TenantID.String(), "error", err)
		}
	}
}
