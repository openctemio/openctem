package controller

// Asset risk score freshness (docs/architecture/asset-risk-score.md):
// asset-risk-score drains the rescore queue that database triggers fill;
// asset-risk-reconcile queues every asset once a day behind the event-driven
// rows, as a safety net for an input no trigger watches.

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
)

var (
	assetRiskQueueDepth = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "openctem", Subsystem: "asset_risk", Name: "queue_depth",
		Help: "Assets waiting for a risk rescore",
	})
	assetRiskQueueOldest = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "openctem", Subsystem: "asset_risk", Name: "queue_oldest_seconds",
		Help: "Age of the oldest due asset in the risk rescore queue",
	})
	assetRiskRescored = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "openctem", Subsystem: "asset_risk", Name: "rescored_total",
		Help: "Assets whose risk score was recomputed",
	})
	assetRiskChanged = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "openctem", Subsystem: "asset_risk", Name: "changed_total",
		Help: "Assets whose stored risk score changed or was set for the first time",
	})
)

// AssetRiskRescorer is the part of the asset service the controllers drive.
type AssetRiskRescorer interface {
	ProcessRiskQueue(ctx context.Context, limit int) (assetapp.RiskQueueResult, error)
	RiskQueueStats(ctx context.Context) (assetdom.RiskQueueStats, error)
	EnqueueRiskReconcile(ctx context.Context, delay time.Duration) (int64, error)
}

// AssetRiskScoreController drains the rescore queue.
type AssetRiskScoreController struct {
	svc      AssetRiskRescorer
	interval time.Duration
	batch    int
	// budget bounds one reconcile: batches are claimed until the queue is
	// empty or the budget is spent, so a large backlog drains over several
	// ticks without holding one tick open.
	budget time.Duration
}

// NewAssetRiskScoreController creates the controller; interval 0 = 10s.
func NewAssetRiskScoreController(svc AssetRiskRescorer, interval time.Duration) *AssetRiskScoreController {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	return &AssetRiskScoreController{
		svc:      svc,
		interval: interval,
		batch:    assetapp.DefaultRiskQueueBatch,
		budget:   interval * 3 / 4,
	}
}

// Name returns the controller name.
func (c *AssetRiskScoreController) Name() string { return "asset-risk-score" }

// Interval returns the reconciliation interval.
func (c *AssetRiskScoreController) Interval() time.Duration { return c.interval }

// Reconcile rescores queued assets. Claims skip locked rows, so replicas may
// run it side by side.
func (c *AssetRiskScoreController) Reconcile(ctx context.Context) (int, error) {
	deadline := time.Now().Add(c.budget)
	total := 0
	var lastErr error
	for {
		res, err := c.svc.ProcessRiskQueue(ctx, c.batch)
		total += res.Scored
		assetRiskRescored.Add(float64(res.Scored))
		assetRiskChanged.Add(float64(res.Changed))
		if err != nil {
			lastErr = err
		}
		if res.Claimed < c.batch || time.Now().After(deadline) || ctx.Err() != nil {
			break
		}
	}
	if stats, err := c.svc.RiskQueueStats(ctx); err == nil {
		assetRiskQueueDepth.Set(float64(stats.Depth))
		assetRiskQueueOldest.Set(stats.OldestAge.Seconds())
	}
	return total, lastErr
}

// AssetRiskReconcileController queues every asset once a day.
type AssetRiskReconcileController struct {
	svc      AssetRiskRescorer
	interval time.Duration
}

// assetRiskReconcileDelay puts reconcile rows behind the rows queued by real
// changes.
const assetRiskReconcileDelay = 10 * time.Minute

// NewAssetRiskReconcileController creates the controller; interval 0 = 24h.
func NewAssetRiskReconcileController(svc AssetRiskRescorer, interval time.Duration) *AssetRiskReconcileController {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	return &AssetRiskReconcileController{svc: svc, interval: interval}
}

// Name returns the controller name.
func (c *AssetRiskReconcileController) Name() string { return "asset-risk-reconcile" }

// Interval returns the reconciliation interval.
func (c *AssetRiskReconcileController) Interval() time.Duration { return c.interval }

// Exclusive: one replica queues the inventory.
func (c *AssetRiskReconcileController) Exclusive() bool { return true }

// Reconcile queues every live asset.
func (c *AssetRiskReconcileController) Reconcile(ctx context.Context) (int, error) {
	n, err := c.svc.EnqueueRiskReconcile(ctx, assetRiskReconcileDelay)
	return int(n), err
}
