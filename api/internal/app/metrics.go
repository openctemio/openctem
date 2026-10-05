package app

import (
	"github.com/openctemio/openctem/api/internal/metrics"
)

// Re-export metrics from the metrics package for backward compatibility.
// New code should import github.com/openctemio/openctem/api/internal/metrics directly.

// Pipeline metrics
var (
	PipelineRunsTotal      = metrics.PipelineRunsTotal
	PipelineRunsInProgress = metrics.PipelineRunsInProgress
	StepRunsTotal          = metrics.StepRunsTotal
)

// Command metrics
var (
	CommandsTotal   = metrics.CommandsTotal
	CommandsExpired = metrics.CommandsExpired
)

// Scan metrics
var (
	ScansScheduled = metrics.ScansScheduled
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
)
