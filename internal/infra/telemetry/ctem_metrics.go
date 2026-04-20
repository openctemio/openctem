// Package telemetry exposes Prometheus metrics for every CTEM stage so
// the loop-closure SLOs in Q4/WS-G have real numbers to alert on.
//
// Q1/WS-G (invariant O1): one counter-in, one counter-out, one latency
// histogram per CTEM stage. Labels are tightly restricted to keep
// cardinality bounded — tenant_id is included because operators need
// per-tenant drill-down, but priority/severity are NOT labels on the
// latency histogram (their cardinality is covered by the counters).
//
// This package only DEFINES metrics — instrumentation sites live in
// the app and handler layers and call the Observe* helpers. That
// separation keeps the metric contract in one file so a CTEM reviewer
// can audit the whole maturity surface here.
package telemetry

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Stage is one of the five CTEM stages. The value is used as a
// metric label; only these constants are allowed so Grafana queries
// stay stable.
type Stage string

const (
	StageScoping        Stage = "scoping"
	StageDiscovery      Stage = "discovery"
	StagePrioritization Stage = "prioritization"
	StageValidation     Stage = "validation"
	StageMobilization   Stage = "mobilization"
)

// AllStages is the canonical ordered list — useful for dashboard
// loops and test coverage.
var AllStages = []Stage{
	StageScoping,
	StageDiscovery,
	StagePrioritization,
	StageValidation,
	StageMobilization,
}

// Outcome is a low-cardinality enum describing what happened to a
// finding as it left a stage.
type Outcome string

const (
	OutcomeAdvanced       Outcome = "advanced"        // moved to the next stage
	OutcomeDeferred       Outcome = "deferred"        // explicitly parked (accepted / compensating control)
	OutcomeFalsePositive  Outcome = "false_positive"  // closed as FP
	OutcomeReopened       Outcome = "reopened"        // came back to this stage from downstream (feedback loop)
	OutcomeFailed         Outcome = "failed"          // stage rejected the item (e.g. validation proved it unexploitable)
	OutcomeClosed         Outcome = "closed"          // terminal
)

var (
	// stageFindingsIn counts findings entering a stage. Labels:
	//   stage     — CTEM stage (canonical string)
	//   tenant_id — owning tenant (so operators can alert per tenant)
	//   priority  — P0..P3 or "unclassified"
	stageFindingsIn = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ctem_stage_findings_in_total",
			Help: "Number of findings entering a CTEM stage.",
		},
		[]string{"stage", "tenant_id", "priority"},
	)

	// stageFindingsOut counts findings leaving a stage with a known
	// outcome. Labels:
	//   stage     — CTEM stage
	//   tenant_id — tenant
	//   outcome   — Outcome constant
	stageFindingsOut = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ctem_stage_findings_out_total",
			Help: "Number of findings leaving a CTEM stage, by outcome.",
		},
		[]string{"stage", "tenant_id", "outcome"},
	)

	// stageLatency is the wall-clock time a finding spent in a stage.
	// Labels:
	//   stage     — CTEM stage
	//   tenant_id — tenant
	//
	// Buckets span seconds..weeks because validation + mobilisation
	// routinely take days. Keep bucket count modest to control
	// histogram memory.
	stageLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "ctem_stage_latency_seconds",
			Help: "Wall-clock latency of a finding within a CTEM stage.",
			Buckets: []float64{
				60,            // 1m
				5 * 60,        // 5m
				15 * 60,       // 15m
				60 * 60,       // 1h
				4 * 60 * 60,   // 4h
				12 * 60 * 60,  // 12h
				24 * 60 * 60,  // 1d
				3 * 86400,     // 3d
				7 * 86400,     // 1w
				30 * 86400,    // 30d
				90 * 86400,    // 90d
			},
		},
		[]string{"stage", "tenant_id"},
	)
)

// ObserveStageIn records that a finding entered a stage. Emit at the
// earliest point the system learns of the finding in that stage.
func ObserveStageIn(stage Stage, tenantID, priority string) {
	if priority == "" {
		priority = "unclassified"
	}
	stageFindingsIn.WithLabelValues(string(stage), tenantID, priority).Inc()
}

// ObserveStageOut records that a finding exited a stage with the
// given outcome.
func ObserveStageOut(stage Stage, tenantID string, outcome Outcome) {
	stageFindingsOut.WithLabelValues(string(stage), tenantID, string(outcome)).Inc()
}

// ObserveStageLatency records wall-clock time spent in a stage.
// Instrumentation sites typically compute `time.Since(stageEnteredAt)`
// and call this helper when the finding exits.
func ObserveStageLatency(stage Stage, tenantID string, d time.Duration) {
	if d <= 0 {
		return // defensive: do not record zero/negative values
	}
	stageLatency.WithLabelValues(string(stage), tenantID).Observe(d.Seconds())
}
