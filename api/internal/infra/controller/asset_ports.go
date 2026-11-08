package controller

// Open ports of assets (docs/architecture/asset-ports.md): asset-ports
// drains the queue that database triggers fill on every port, address and
// edge change, so the asset list's port and service filters read current
// rows.

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/openctemio/openctem/api/pkg/domain/assetport"
)

var (
	assetPortQueueDepth = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: assetDomainMetricsNamespace, Subsystem: "asset_ports", Name: "queue_depth",
		Help: "Assets waiting for their open ports to be recomputed",
	})
	assetPortRefreshed = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: assetDomainMetricsNamespace, Subsystem: "asset_ports", Name: "refreshed_total",
		Help: "Assets whose open ports were recomputed",
	})
)

// AssetPortQueue is the store the controller drives.
type AssetPortQueue interface {
	ProcessQueue(ctx context.Context, limit int) (assetport.QueueResult, error)
	QueueDepth(ctx context.Context) (int64, error)
}

// assetPortBatch is the queued assets one batch claims.
const assetPortBatch = 500

// AssetPortsController drains the asset ports queue.
type AssetPortsController struct {
	q        AssetPortQueue
	interval time.Duration
	budget   time.Duration
}

// NewAssetPortsController creates the controller; interval 0 = 10s.
func NewAssetPortsController(q AssetPortQueue, interval time.Duration) *AssetPortsController {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	return &AssetPortsController{q: q, interval: interval, budget: interval * 3 / 4}
}

// Name returns the controller name.
func (c *AssetPortsController) Name() string { return "asset-ports" }

// Interval returns the reconciliation interval.
func (c *AssetPortsController) Interval() time.Duration { return c.interval }

// Reconcile processes batches until the queue is empty or the budget is
// spent. Claims skip locked rows, so replicas may run it side by side.
func (c *AssetPortsController) Reconcile(ctx context.Context) (int, error) {
	deadline := time.Now().Add(c.budget)
	total := 0
	for {
		res, err := c.q.ProcessQueue(ctx, assetPortBatch)
		total += res.Refreshed
		assetPortRefreshed.Add(float64(res.Refreshed))
		if err != nil {
			return total, err
		}
		if res.Claimed < assetPortBatch || time.Now().After(deadline) || ctx.Err() != nil {
			break
		}
	}
	if n, err := c.q.QueueDepth(ctx); err == nil {
		assetPortQueueDepth.Set(float64(n))
	}
	return total, nil
}
