package app

import (
	"github.com/openctemio/api/internal/metrics"
)

// Re-export metrics from the metrics package for backward compatibility.
// New code should import github.com/openctemio/api/internal/metrics directly.

// Pipeline metrics
var (
	PipelineRunsTotal      = metrics.PipelineRunsTotal
	PipelineRunDuration    = metrics.PipelineRunDuration
	PipelineRunsInProgress = metrics.PipelineRunsInProgress
	StepRunsTotal          = metrics.StepRunsTotal
	StepRunDuration        = metrics.StepRunDuration
	StepRetryTotal         = metrics.StepRetryTotal
)

// Command metrics
var (
	CommandsTotal    = metrics.CommandsTotal
	CommandDuration  = metrics.CommandDuration
	CommandsExpired  = metrics.CommandsExpired
	CommandQueueSize = metrics.CommandQueueSize
)

// Agent metrics
var (
	AgentsOnline          = metrics.AgentsOnline
	AgentCommandsExecuted = metrics.AgentCommandsExecuted
	AgentHeartbeatLatency = metrics.AgentHeartbeatLatency
)

// Scan metrics
var (
	ScansTotal              = metrics.ScansTotal
	ScansScheduled          = metrics.ScansScheduled
	ScanFindingsTotal       = metrics.ScanFindingsTotal
	ScanTriggerDuration     = metrics.ScanTriggerDuration
	ScanSchedulerErrors     = metrics.ScanSchedulerErrors
	ScanSchedulerLag        = metrics.ScanSchedulerLag
	ScansConcurrentRuns     = metrics.ScansConcurrentRuns
	ScansQualityGateResults = metrics.ScansQualityGateResults
)

// Finding lifecycle metrics
var (
	FindingsExpired      = metrics.FindingsExpired
	FindingsAutoResolved = metrics.FindingsAutoResolved
)

// Template sync metrics
var (
	TemplateSyncsTotal        = metrics.TemplateSyncsTotal
	TemplateSyncsSuccessTotal = metrics.TemplateSyncsSuccessTotal
	TemplateSyncsFailedTotal  = metrics.TemplateSyncsFailedTotal
	TemplateSyncDuration      = metrics.TemplateSyncDuration
)
