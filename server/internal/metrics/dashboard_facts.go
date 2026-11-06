package metrics

// Dashboard fact layer upkeep (docs/architecture/dashboards.md, "Facts
// maintainer"). No tenant label: the alerts leave the platform.

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// DashboardFactLagSeconds is, for every claimed batch of change marks,
	// how long its oldest mark waited: write to fact (target p95 < 2 min).
	DashboardFactLagSeconds = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "openctem_dashboard_fact_lag_seconds",
			Help:    "Age of the oldest change mark of each processed batch (write to dashboard fact)",
			Buckets: []float64{1, 5, 15, 30, 60, 120, 300, 600, 1800, 3600},
		},
	)

	// DashboardFactQueueDepth is the number of unprocessed change marks.
	DashboardFactQueueDepth = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "openctem_dashboard_fact_queue_depth",
			Help: "Unprocessed dashboard fact change marks, all tenants",
		},
	)

	// DashboardFactQueueOldestSeconds is the age of the oldest unprocessed
	// change mark (0 when the queue is empty).
	DashboardFactQueueOldestSeconds = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "openctem_dashboard_fact_queue_oldest_seconds",
			Help: "Age of the oldest unprocessed dashboard fact change mark (0 = empty queue)",
		},
	)

	// DashboardFactDriftRowsTotal counts fact rows a requested rebuild or the
	// nightly reconciliation corrected that no change mark explained. Any
	// increase is a bug (a write path that was not marked, or a recompute
	// error), never noise.
	DashboardFactDriftRowsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_dashboard_fact_drift_rows_total",
			Help: "Dashboard fact rows corrected by a full run that no change mark explained (should stay 0)",
		},
		[]string{"kind"},
	)

	// DashboardFactRunsTotal counts completed full runs by kind: initial,
	// requested, nightly.
	DashboardFactRunsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_dashboard_fact_runs_total",
			Help: "Completed full runs of a tenant's dashboard facts by kind",
		},
		[]string{"kind"},
	)
)
