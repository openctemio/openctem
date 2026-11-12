package controller

// Domain membership of assets (docs/architecture/asset-domain-membership.md):
// asset-domain-membership drains the queue that database triggers fill on
// every asset and edge change, so the findings asset_domain filter reads
// current keys.

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/openctemio/openctem/server/pkg/domain/assetdomain"
)

// assetDomainMetrics is the namespace and subsystem of the worker's metrics.
const (
	assetDomainMetricsNamespace = "openctem"
	assetDomainMetricsSubsystem = "asset_domain"
	assetDomainQueueDepthName   = "queue_depth"
)

var (
	assetDomainQueueDepth = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: assetDomainMetricsNamespace, Subsystem: assetDomainMetricsSubsystem, Name: assetDomainQueueDepthName,
		Help: "Assets waiting for their domain membership to be recomputed",
	})
	assetDomainRefreshed = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: assetDomainMetricsNamespace, Subsystem: assetDomainMetricsSubsystem, Name: "refreshed_total",
		Help: "Assets whose domain membership was recomputed",
	})
)

// AssetDomainQueue is the membership store the controller drives.
type AssetDomainQueue interface {
	ProcessQueue(ctx context.Context, limit int) (assetdomain.QueueResult, error)
	QueueDepth(ctx context.Context) (int64, error)
}

// assetDomainBatch is the queued assets one batch claims.
const assetDomainBatch = 500

// AssetDomainMembershipController drains the membership queue.
type AssetDomainMembershipController struct {
	q        AssetDomainQueue
	interval time.Duration
	budget   time.Duration
}

// NewAssetDomainMembershipController creates the controller; interval 0 = 10s.
func NewAssetDomainMembershipController(q AssetDomainQueue, interval time.Duration) *AssetDomainMembershipController {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	return &AssetDomainMembershipController{q: q, interval: interval, budget: interval * 3 / 4}
}

// Name returns the controller name.
func (c *AssetDomainMembershipController) Name() string { return "asset-domain-membership" }

// Interval returns the reconciliation interval.
func (c *AssetDomainMembershipController) Interval() time.Duration { return c.interval }

// Reconcile processes batches until the queue is empty or the budget is
// spent. Claims skip locked rows, so replicas may run it side by side.
func (c *AssetDomainMembershipController) Reconcile(ctx context.Context) (int, error) {
	deadline := time.Now().Add(c.budget)
	total := 0
	for {
		res, err := c.q.ProcessQueue(ctx, assetDomainBatch)
		total += res.Refreshed
		assetDomainRefreshed.Add(float64(res.Refreshed))
		if err != nil {
			return total, err
		}
		if res.Claimed < assetDomainBatch || time.Now().After(deadline) || ctx.Err() != nil {
			break
		}
	}
	if n, err := c.q.QueueDepth(ctx); err == nil {
		assetDomainQueueDepth.Set(float64(n))
	}
	return total, nil
}
