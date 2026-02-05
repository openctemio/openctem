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

// Agent metrics
var (
	// AgentsOnline tracks online agents
	AgentsOnline = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "agents_online",
			Help: "Number of online agents",
		},
		[]string{"tenant_id"},
	)

	// AgentCommandsExecuted tracks commands executed by agents
	AgentCommandsExecuted = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "agent_commands_executed_total",
			Help: "Total commands executed by agents",
		},
		[]string{"tenant_id", "agent_id", "status"},
	)

	// AgentHeartbeatLatency tracks agent heartbeat latency
	AgentHeartbeatLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "agent_heartbeat_latency_seconds",
			Help:    "Agent heartbeat latency in seconds",
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
