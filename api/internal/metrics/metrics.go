// Package metrics
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Scan workflow metrics
var (
	// ScanRunsTotal tracks total scan runs by status
	ScanRunsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "scan_runs_total",
			Help: "Total number of scan runs by status",
		},
		[]string{"status"},
	)

	// ScanRunsInProgress tracks currently running scan workflows
	ScanRunsInProgress = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "scan_runs_in_progress",
			Help: "Number of scan runs currently in progress",
		},
		[]string{},
	)

	// StepRunsTotal tracks total step runs by status
	StepRunsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "scan_run_steps_total",
			Help: "Total number of step runs by status",
		},
		[]string{"step_key", "status"},
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
		[]string{"type", "status"},
	)

	// CommandsExpired tracks expired commands
	CommandsExpired = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "commands_expired_total",
			Help: "Total number of expired commands",
		},
		[]string{},
	)
)

// Scan metrics
var (
	// ScanScheduleOutcomes counts what each due scheduled occurrence became:
	// triggered, skipped_overlap (previous run still active), failed.
	ScanScheduleOutcomes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "scan_schedule_outcomes_total",
			Help: "Scheduled scan occurrences by outcome (triggered, skipped_overlap, failed)",
		},
		[]string{"outcome"},
	)

	// ScansScheduled tracks scheduled scan triggers
	ScansScheduled = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "scans_scheduled_total",
			Help: "Total number of scheduled scan triggers",
		},
		[]string{},
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
		[]string{"reason"},
	)

	// FindingsAutoResolved tracks findings auto-resolved by full coverage scans
	FindingsAutoResolved = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "findings_auto_resolved_total",
			Help: "Total number of findings auto-resolved by full coverage scans",
		},
		[]string{},
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
		[]string{"source_type"},
	)

	// TemplateSyncsSuccessTotal tracks successful template syncs
	TemplateSyncsSuccessTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "template_syncs_success_total",
			Help: "Total number of successful template sync operations",
		},
		[]string{},
	)

	// TemplateSyncsFailedTotal tracks failed template syncs
	TemplateSyncsFailedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "template_syncs_failed_total",
			Help: "Total number of failed template sync operations",
		},
		[]string{},
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

	// SensorUnsolicitedResultsTotal counts sensor reports that named no
	// command (RFC-040 §5.3), by what happened to them: applied (a collector
	// or CI runner), warned (another role, applied because the tenant's mode
	// is warn), quarantined, or refused (the quarantine was full).
	SensorUnsolicitedResultsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sensor_unsolicited_results_total",
			Help: "Sensor reports without a command, by outcome (applied, warned, quarantined, refused)",
		},
		[]string{"outcome"},
	)

	// SensorResultChangesWithheldTotal counts changes a sensor report was not
	// allowed to make because no command covering the object stood behind
	// it (RFC-040 §5.3): kind asset (an existing asset left unchanged) or
	// reopen (a finding a person resolved left resolved).
	SensorResultChangesWithheldTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sensor_result_changes_withheld_total",
			Help: "Changes withheld from sensor reports with no command covering the object, by kind (asset, reopen)",
		},
		[]string{"kind"},
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

	// FindingsCoverageAutoResolve counts findings that coverage-scoped
	// auto-resolve closed ("resolved"), would have closed in dry-run mode
	// ("would_resolve") or held behind the blinding guard ("held").
	FindingsCoverageAutoResolve = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "findings_coverage_auto_resolve_total",
			Help: "Non-repository findings closed, or that would be closed, by coverage-scoped auto-resolve, by mode and result",
		},
		[]string{"mode", "result"},
	)

	// CoverageAutoResolveEvaluations counts coverage evaluations of scan
	// commands by mode and decision (eligible or why not).
	CoverageAutoResolveEvaluations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "coverage_auto_resolve_evaluations_total",
			Help: "Coverage-scoped auto-resolve evaluations of scan commands, by mode and decision",
		},
		[]string{"mode", "decision"},
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

	// SensorProtocolRequestsTotal counts sensor requests by protocol version
	// and route name, both from closed sets (RFC-029 §5.3).
	SensorProtocolRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sensor_protocol_requests_total",
			Help: "Sensor protocol requests, by protocol version and route",
		},
		[]string{"protocol", "route"},
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

// Dispatch (RFC-046 §12). No tenant, sensor or run labels (B9): per-tenant
// views come from logs and traces.
var (
	// CommandClaimsTotal counts commands sensors claimed, by how: "claim"
	// (one by id) or "claim_n" (claimed by the poll).
	CommandClaimsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "command_claims_total",
			Help: "Commands claimed by sensors, by mode (claim, claim_n)",
		},
		[]string{"mode"},
	)

	// CommandLeasesExpiredTotal counts commands taken back from a sensor
	// whose lease ran out (it stopped renewing) and re-queued.
	CommandLeasesExpiredTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "command_leases_expired_total",
			Help: "Commands re-queued because the sensor holding them let the lease expire",
		},
	)

	// ScanRunsReapedTotal counts runs the timeout controller ended, by
	// reason: "deadline" (past its deadline; ends partial or timeout) or
	// "unclaimed" (no sensor picked any work up in time).
	ScanRunsReapedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "scan_runs_reaped_total",
			Help: "Scan runs ended by the timeout controller, by reason (deadline, unclaimed)",
		},
		[]string{"reason"},
	)

	// JobSigningTotal counts claimed commands sent to the job signer, by
	// outcome: "signed", "refused" (the signer said no) or "unavailable"
	// (no answer). A command not signed is not handed out.
	JobSigningTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sensor_job_signing_total",
			Help: "Claimed commands sent to the job signer, by outcome (signed, refused, unavailable)",
		},
		[]string{"outcome"},
	)

	// SignerRefusalsTotal counts the job signer's refusals by reason
	// (out_of_ledger, tier_exceeds_ledger, target_excluded, rate limits,
	// malformed statements; RFC-040 §5.11 detection A10). The signer's own
	// signing log is the record a compromised API cannot rewrite; this is
	// the alerting signal.
	SignerRefusalsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_signer_refusals_total",
			Help: "Job statements the job signer refused, by reason",
		},
		[]string{"reason"},
	)

	// SignerLedgerFeedTotal counts scope changes sent to the job signer's
	// ledger, by kind (widen, narrow, sync) and outcome (applied, refused,
	// unavailable).
	SignerLedgerFeedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_signer_ledger_feed_total",
			Help: "Scope changes sent to the job signer's ledger, by kind and outcome",
		},
		[]string{"kind", "outcome"},
	)
)
