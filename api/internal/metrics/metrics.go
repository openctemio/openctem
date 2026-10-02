// Package metrics
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Pipeline metrics
var (
	// PipelineRunsTotal tracks total pipeline runs by status
	PipelineRunsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pipeline_runs_total",
			Help: "Total number of pipeline runs by status",
		},
		[]string{"tenant_id", "status"},
	)

	// PipelineRunDuration tracks pipeline run duration
	PipelineRunDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "pipeline_run_duration_seconds",
			Help:    "Pipeline run duration in seconds",
			Buckets: []float64{1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600},
		},
		[]string{"tenant_id", "pipeline_id"},
	)

	// PipelineRunsInProgress tracks currently running pipelines
	PipelineRunsInProgress = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pipeline_runs_in_progress",
			Help: "Number of pipeline runs currently in progress",
		},
		[]string{"tenant_id"},
	)

	// StepRunsTotal tracks total step runs by status
	StepRunsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "step_runs_total",
			Help: "Total number of step runs by status",
		},
		[]string{"tenant_id", "step_key", "status"},
	)

	// StepRunDuration tracks step run duration
	StepRunDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "step_run_duration_seconds",
			Help:    "Step run duration in seconds",
			Buckets: []float64{0.1, 0.5, 1, 5, 10, 30, 60, 120, 300, 600},
		},
		[]string{"tenant_id", "step_key"},
	)

	// StepRetryTotal tracks step retries
	StepRetryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "step_retry_total",
			Help: "Total number of step retries",
		},
		[]string{"tenant_id", "step_key"},
	)
)

// Command metrics
var (
	// CommandsTotal tracks total commands by type and status
	CommandsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "commands_total",
			Help: "Total number of commands by type and status",
		},
		[]string{"tenant_id", "type", "status"},
	)

	// CommandDuration tracks command execution duration
	CommandDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "command_duration_seconds",
			Help:    "Command execution duration in seconds",
			Buckets: []float64{0.1, 0.5, 1, 5, 10, 30, 60, 120, 300, 600},
		},
		[]string{"tenant_id", "type"},
	)

	// CommandsExpired tracks expired commands
	CommandsExpired = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "commands_expired_total",
			Help: "Total number of expired commands",
		},
		[]string{"tenant_id"},
	)

	// CommandQueueSize tracks pending commands
	CommandQueueSize = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "command_queue_size",
			Help: "Number of pending commands in queue",
		},
		[]string{"tenant_id", "type"},
	)
)

// Sensor metrics
var (
	// SensorsOnline tracks online sensors
	SensorsOnline = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sensors_online",
			Help: "Number of online sensors",
		},
		[]string{"tenant_id"},
	)

	// SensorCommandsExecuted tracks commands executed by sensors
	SensorCommandsExecuted = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sensor_commands_executed_total",
			Help: "Total commands executed by sensors",
		},
		[]string{"tenant_id", "sensor_id", "status"},
	)

	// SensorHeartbeatLatency tracks sensor heartbeat latency
	SensorHeartbeatLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sensor_heartbeat_latency_seconds",
			Help:    "Sensor heartbeat latency in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
		},
		[]string{"tenant_id"},
	)
)

// Scan metrics
var (
	// ScansTotal tracks total scans by status
	ScansTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "scans_total",
			Help: "Total number of scans by status",
		},
		[]string{"tenant_id", "scan_type", "status"},
	)

	// ScansScheduled tracks scheduled scan triggers
	ScansScheduled = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "scans_scheduled_total",
			Help: "Total number of scheduled scan triggers",
		},
		[]string{"tenant_id"},
	)

	// ScanFindingsTotal tracks total findings from scans
	ScanFindingsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "scan_findings_total",
			Help: "Total number of findings from scans",
		},
		[]string{"tenant_id", "severity"},
	)

	// ScanTriggerDuration tracks scan trigger latency
	ScanTriggerDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "scan_trigger_duration_seconds",
			Help:    "Time to trigger a scan in seconds",
			Buckets: []float64{0.1, 0.5, 1, 2, 5, 10, 30},
		},
		[]string{"scan_type"},
	)

	// ScanSchedulerErrors tracks scheduler errors by type
	ScanSchedulerErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "scan_scheduler_errors_total",
			Help: "Total number of scan scheduler errors",
		},
		[]string{"error_type"},
	)

	// ScanSchedulerLag tracks time since last scheduler cycle
	ScanSchedulerLag = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "scan_scheduler_lag_seconds",
			Help: "Time since last scheduler cycle in seconds",
		},
	)

	// ScansConcurrentRuns tracks current concurrent scan runs per tenant
	ScansConcurrentRuns = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "scans_concurrent_runs",
			Help: "Number of concurrent scan runs",
		},
		[]string{"tenant_id"},
	)

	// ScansQualityGateResults tracks quality gate pass/fail results
	ScansQualityGateResults = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "scans_quality_gate_results_total",
			Help: "Total quality gate evaluation results",
		},
		[]string{"tenant_id", "result"}, // result: "passed", "failed"
	)
)

// Finding lifecycle metrics
var (
	// FindingsExpired tracks findings expired by lifecycle rules
	FindingsExpired = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "findings_expired_total",
			Help: "Total number of findings expired by lifecycle rules",
		},
		[]string{"tenant_id", "reason"},
	)

	// FindingsAutoResolved tracks findings auto-resolved by full coverage scans
	FindingsAutoResolved = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "findings_auto_resolved_total",
			Help: "Total number of findings auto-resolved by full coverage scans",
		},
		[]string{"tenant_id"},
	)
)

// Template sync metrics
var (
	// TemplateSyncsTotal tracks total template sync operations
	TemplateSyncsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "template_syncs_total",
			Help: "Total number of template sync operations by source type",
		},
		[]string{"tenant_id", "source_type"},
	)

	// TemplateSyncsSuccessTotal tracks successful template syncs
	TemplateSyncsSuccessTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "template_syncs_success_total",
			Help: "Total number of successful template sync operations",
		},
		[]string{"tenant_id"},
	)

	// TemplateSyncsFailedTotal tracks failed template syncs
	TemplateSyncsFailedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "template_syncs_failed_total",
			Help: "Total number of failed template sync operations",
		},
		[]string{"tenant_id"},
	)

	// TemplateSyncDuration tracks template sync duration
	TemplateSyncDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "template_sync_duration_seconds",
			Help:    "Template sync duration in seconds",
			Buckets: []float64{1, 5, 10, 30, 60, 120, 300, 600},
		},
		[]string{"tenant_id", "source_type"},
	)
)

// Async ingest metrics (RFC-005). Exposed so operators can watch queue depth,
// throughput, and end-to-end latency before/while running INGEST_MODE=async.
var (
	// IngestJobsEnqueuedTotal counts payloads accepted into the async queue.
	// The "duplicate" label is "true" when an identical payload was already
	// queued (idempotency hit).
	IngestJobsEnqueuedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ingest_jobs_enqueued_total",
			Help: "Total async ingest jobs enqueued, by duplicate (idempotency) status",
		},
		[]string{"duplicate"},
	)

	// IngestJobsProcessedTotal counts worker outcomes: completed, retried, dead.
	IngestJobsProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ingest_jobs_processed_total",
			Help: "Total async ingest jobs processed by the worker, by outcome",
		},
		[]string{"outcome"},
	)

	// IngestJobDurationSeconds is end-to-end latency from enqueue to completion.
	IngestJobDurationSeconds = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "ingest_job_duration_seconds",
			Help:    "End-to-end async ingest latency (enqueue to completion) in seconds",
			Buckets: []float64{0.1, 0.5, 1, 5, 10, 30, 60, 120, 300, 600, 1800},
		},
	)

	// Sensor protocol v2 results (RFC-026). Every label comes from a closed
	// set (route names, problem types, fixed outcomes), never from a tool
	// name, an id or any other sensor-supplied string.

	// IngestV2RequestsTotal counts answered v2 requests by route, method,
	// outcome (accepted, ok, refused) and problem type ("none" on success).
	IngestV2RequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ingest_v2_requests_total",
			Help: "Sensor protocol v2 requests (results and, since RFC-029, the control plane), by route, method, outcome and problem type",
		},
		[]string{"route", "method", "outcome", "problem"},
	)

	// IngestV2Bytes is the size of accepted v2 request content, as sent
	// (encoded) and after the content coding was removed (decoded).
	IngestV2Bytes = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ingest_v2_bytes",
			Help:    "Sensor protocol v2 results content size in bytes, by stage (encoded, decoded)",
			Buckets: prometheus.ExponentialBuckets(1024, 4, 10), // 1 KiB .. 256 MiB
		},
		[]string{"stage"},
	)

	// IngestV2ItemsTotal counts processed v2 items by kind (asset, finding)
	// and result (accepted, rejected, quarantined).
	IngestV2ItemsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ingest_v2_items_total",
			Help: "Sensor protocol v2 results items processed, by kind and result",
		},
		[]string{"kind", "result"},
	)

	// IngestV2ReportsTotal counts v2 reports reaching a final state, with the
	// commit's auto-resolve outcome (applied, held, skipped; "none" for
	// expired and failed reports).
	IngestV2ReportsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ingest_v2_reports_total",
			Help: "Sensor protocol v2 results reports reaching a final state, by state and auto-resolve outcome",
		},
		[]string{"state", "auto_resolve"},
	)

	// SensorProtocolRequestsTotal counts sensor requests by protocol ("1",
	// "2") and route name, both from closed sets: the fleet view of who
	// still speaks the deprecated protocol v1 (RFC-029 §5.3).
	SensorProtocolRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sensor_protocol_requests_total",
			Help: "Sensor protocol requests, by protocol version and route",
		},
		[]string{"protocol", "route"},
	)

	// IngestV1RequestsTotal counts protocol v1 ingest requests per route, to
	// measure who still uses which v1 route before any is retired
	// (RFC-026 §8.3).
	IngestV1RequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ingest_v1_requests_total",
			Help: "Sensor protocol v1 ingest requests, by route",
		},
		[]string{"route"},
	)

	// IngestQueueDepth is the number of not-yet-terminal (pending+processing)
	// jobs, refreshed each worker cycle. The key backpressure signal.
	IngestQueueDepth = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ingest_queue_depth",
			Help: "Async ingest jobs awaiting or in processing across all tenants",
		},
	)
)
