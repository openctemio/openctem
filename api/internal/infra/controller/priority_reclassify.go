package controller

// Finding-priority recompute (docs/architecture/scoring-versions.md).
//
// Producers (control changes, attribution, AI triage, threat intel) and
// database triggers (new findings, reopen, severity, asset context, tenant
// scoring settings) queue assets in the durable finding_priority_queue. The
// finding-priority worker claims them tenant-fair and recomputes the
// priority class and SLA deadline of their OPEN findings; closed findings are
// never touched. The reconcile queues findings whose scoring version is
// stale (a new model or settings) at once and everything else once a day.

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/openctemio/openctem/api/pkg/domain/scoring"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ReclassifyReasonKind enumerates why assets were queued.
type ReclassifyReasonKind string

const (
	ReasonKEVRefresh    ReclassifyReasonKind = "kev_refresh"
	ReasonControlChange ReclassifyReasonKind = "control_change"
	ReasonAssetChange   ReclassifyReasonKind = "asset_change"
	// ReasonAITriage is queued when an AI triage completes for a finding, so a
	// high-confidence "likely false positive" verdict can de-escalate it.
	ReasonAITriage ReclassifyReasonKind = "ai_triage"
)

// ReclassifyRequest describes assets whose open findings need a new
// priority. AssetIDs empty = every asset of the tenant with an open finding.
type ReclassifyRequest struct {
	TenantID shared.ID
	Reason   ReclassifyReasonKind
	AssetIDs []shared.ID
}

// ReclassifyQueue accepts reclassify requests.
type ReclassifyQueue interface {
	Enqueue(ctx context.Context, req ReclassifyRequest) error
}

var (
	findingPriorityQueueDepth = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "openctem", Subsystem: "finding_priority", Name: "queue_depth",
		Help: "Assets whose open findings wait for a priority recompute",
	})
	findingPriorityQueueOldest = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "openctem", Subsystem: "finding_priority", Name: "queue_oldest_seconds",
		Help: "Age of the oldest due asset in the finding-priority queue",
	})
	findingPriorityChecked = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "openctem", Subsystem: "finding_priority", Name: "checked_total",
		Help: "Open findings whose priority was recomputed",
	})
	findingPriorityChanged = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "openctem", Subsystem: "finding_priority", Name: "changed_total",
		Help: "Findings whose priority class changed",
	})
)

// FindingPriorityProcessor is the worker's view of the reclassifier.
type FindingPriorityProcessor interface {
	ProcessQueue(ctx context.Context, limit, perTenant int) (scoring.QueueResult, error)
	QueueStats(ctx context.Context) (scoring.QueueStats, error)
	EnqueueReconcile(ctx context.Context, delay time.Duration) (int64, error)
}

// FindingPriorityController drains the finding-priority queue.
type FindingPriorityController struct {
	svc       FindingPriorityProcessor
	interval  time.Duration
	batch     int
	perTenant int
	// budget bounds one Reconcile so a large backlog cannot pin a tick.
	budget time.Duration
}

// NewFindingPriorityController builds the worker; interval <= 0 means 10 s.
func NewFindingPriorityController(svc FindingPriorityProcessor, interval time.Duration, batch, perTenant int) *FindingPriorityController {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	if batch <= 0 {
		batch = 200
	}
	if perTenant <= 0 {
		perTenant = 50
	}
	return &FindingPriorityController{svc: svc, interval: interval, batch: batch, perTenant: perTenant, budget: interval * 3 / 4}
}

// Name returns the controller name.
func (c *FindingPriorityController) Name() string { return "finding-priority" }

// Interval returns how often the queue is drained.
func (c *FindingPriorityController) Interval() time.Duration { return c.interval }

// Reconcile drains due rows until the queue is empty or the budget is spent.
func (c *FindingPriorityController) Reconcile(ctx context.Context) (int, error) {
	deadline := time.Now().Add(c.budget)
	total := 0
	var lastErr error
	for {
		res, err := c.svc.ProcessQueue(ctx, c.batch, c.perTenant)
		total += res.Checked
		findingPriorityChecked.Add(float64(res.Checked))
		findingPriorityChanged.Add(float64(res.Changed))
		if err != nil {
			lastErr = err
		}
		if res.Claimed < c.batch || time.Now().After(deadline) || ctx.Err() != nil {
			break
		}
	}
	if stats, err := c.svc.QueueStats(ctx); err == nil {
		findingPriorityQueueDepth.Set(float64(stats.Depth))
		findingPriorityQueueOldest.Set(stats.OldestAge.Seconds())
	}
	return total, lastErr
}

// FindingPriorityReconcileController queues stale findings at once and every
// other open finding behind the event-driven rows, once a day and at start-up.
// It is the safety net for inputs no trigger watches (attack-path
// reachability, the threat model) and for a crashed pass.
type FindingPriorityReconcileController struct {
	svc      FindingPriorityProcessor
	interval time.Duration
}

// findingPriorityReconcileDelay puts the daily full pass behind events.
const findingPriorityReconcileDelay = 10 * time.Minute

// NewFindingPriorityReconcileController builds the reconcile; interval <= 0
// means daily.
func NewFindingPriorityReconcileController(svc FindingPriorityProcessor, interval time.Duration) *FindingPriorityReconcileController {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	return &FindingPriorityReconcileController{svc: svc, interval: interval}
}

// Name returns the controller name.
func (c *FindingPriorityReconcileController) Name() string { return "finding-priority-reconcile" }

// Interval returns the reconcile period.
func (c *FindingPriorityReconcileController) Interval() time.Duration { return c.interval }

// Exclusive runs it on one replica at a time.
func (c *FindingPriorityReconcileController) Exclusive() bool { return true }

// Reconcile queues the work.
func (c *FindingPriorityReconcileController) Reconcile(ctx context.Context) (int, error) {
	n, err := c.svc.EnqueueReconcile(ctx, findingPriorityReconcileDelay)
	return int(n), err
}
