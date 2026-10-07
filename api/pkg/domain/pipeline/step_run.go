package pipeline

import (
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// StepRunStatus represents the status of a step run.
type StepRunStatus string

const (
	StepRunStatusPending   StepRunStatus = "pending"
	StepRunStatusQueued    StepRunStatus = "queued"
	StepRunStatusRunning   StepRunStatus = "running"
	StepRunStatusCompleted StepRunStatus = "completed"
	// StepRunStatusPartial: a batched step where some batches completed and
	// some failed. Its results are kept and it unblocks dependent steps
	// (RFC-046 D5).
	StepRunStatusPartial  StepRunStatus = "partial"
	StepRunStatusFailed   StepRunStatus = "failed"
	StepRunStatusSkipped  StepRunStatus = "skipped"
	StepRunStatusCanceled StepRunStatus = "canceled"
	StepRunStatusTimeout  StepRunStatus = "timeout"
)

// IsValid checks if the step run status is valid.
func (s StepRunStatus) IsValid() bool {
	switch s {
	case StepRunStatusPending, StepRunStatusQueued, StepRunStatusRunning,
		StepRunStatusCompleted, StepRunStatusPartial, StepRunStatusFailed, StepRunStatusSkipped,
		StepRunStatusCanceled, StepRunStatusTimeout:
		return true
	}
	return false
}

// IsTerminal checks if the status is terminal.
func (s StepRunStatus) IsTerminal() bool {
	switch s {
	case StepRunStatusCompleted, StepRunStatusPartial, StepRunStatusFailed, StepRunStatusSkipped,
		StepRunStatusCanceled, StepRunStatusTimeout:
		return true
	}
	return false
}

// ErrStepRunAlreadyFinished is returned when a write would move a step run that
// already reached a terminal state (completed, partial, failed, skipped,
// canceled, timeout). Like a run, a finished step is final: a duplicate or late sensor
// result, a cancel or timeout racing a completion, or a stale in-memory copy
// must not reopen it, re-queue it or overwrite its outcome and findings count.
var ErrStepRunAlreadyFinished = shared.NewDomainError("STEP_RUN_ALREADY_FINISHED",
	"step run has already finished", shared.ErrConflict)

// IsSuccess checks if the status indicates success.
func (s StepRunStatus) IsSuccess() bool {
	return s == StepRunStatusCompleted
}

// ProducedResults reports whether a finished step produced results its
// dependents can build on: completed, or partial (some batches failed, the
// others' results are kept).
func (s StepRunStatus) ProducedResults() bool {
	return s == StepRunStatusCompleted || s == StepRunStatusPartial
}

// StepRun represents an execution of a pipeline step.
type StepRun struct {
	ID            shared.ID
	PipelineRunID shared.ID
	// StepID is the pipeline step this run executed. It is zero once that
	// step was removed from the pipeline: the step run keeps its history
	// (StepKey, StepName, Tool) and is never deleted with the step.
	StepID shared.ID

	// Step identification, copied from the step when the step run was
	// created, so history says what ran after the step is edited or removed.
	StepKey   string
	StepOrder int
	StepName  string
	Tool      string

	// Execution
	Status StepRunStatus

	// Sensor assignment
	SensorID  *shared.ID
	CommandID *shared.ID

	// Condition evaluation
	ConditionEvaluated bool
	ConditionResult    *bool
	SkipReason         string

	// Results
	FindingsCount int
	Output        map[string]any

	// Retry tracking
	Attempt     int
	MaxAttempts int

	// Timing
	QueuedAt    *time.Time
	StartedAt   *time.Time
	CompletedAt *time.Time

	// Error info
	ErrorMessage string
	ErrorCode    string

	// Timestamps
	CreatedAt time.Time
}

// NewStepRun creates a new step run.
func NewStepRun(
	pipelineRunID shared.ID,
	stepID shared.ID,
	stepKey string,
	order int,
	maxRetries int,
) *StepRun {
	return &StepRun{
		ID:            shared.NewID(),
		PipelineRunID: pipelineRunID,
		StepID:        stepID,
		StepKey:       stepKey,
		StepOrder:     order,
		Status:        StepRunStatusPending,
		Output:        make(map[string]any),
		Attempt:       1,
		MaxAttempts:   1 + maxRetries,
		CreatedAt:     time.Now(),
	}
}

// NewStepRunForStep creates the step run of a step and records the step's
// name and tool on it, so the run's history stays readable after the step
// is edited or removed.
func NewStepRunForStep(pipelineRunID shared.ID, step *Step) *StepRun {
	sr := NewStepRun(pipelineRunID, step.ID, step.StepKey, step.StepOrder, step.MaxRetries)
	sr.StepName = step.Name
	sr.Tool = step.Tool
	return sr
}

// Queue marks the step as queued for execution.
func (sr *StepRun) Queue() {
	now := time.Now()
	sr.QueuedAt = &now
	sr.Status = StepRunStatusQueued
}

// Start marks the step as started.
func (sr *StepRun) Start(sensorID, commandID shared.ID) {
	now := time.Now()
	sr.StartedAt = &now
	sr.Status = StepRunStatusRunning
	sr.SensorID = &sensorID
	sr.CommandID = &commandID
}

// Complete marks the step as completed.
func (sr *StepRun) Complete(findingsCount int, output map[string]any) {
	now := time.Now()
	sr.CompletedAt = &now
	sr.Status = StepRunStatusCompleted
	sr.FindingsCount = findingsCount
	if output != nil {
		sr.Output = output
	}
}

// Partial marks a batched step that kept some batches' results and lost
// others. message says how many batches failed and why.
func (sr *StepRun) Partial(findingsCount int, message, errorCode string) {
	now := time.Now()
	sr.CompletedAt = &now
	sr.Status = StepRunStatusPartial
	sr.FindingsCount = findingsCount
	sr.ErrorMessage = message
	sr.ErrorCode = errorCode
}

// Fail marks the step as failed.
func (sr *StepRun) Fail(errorMessage, errorCode string) {
	now := time.Now()
	sr.CompletedAt = &now
	sr.Status = StepRunStatusFailed
	sr.ErrorMessage = errorMessage
	sr.ErrorCode = errorCode
}

// Skip marks the step as skipped.
func (sr *StepRun) Skip(reason string) {
	now := time.Now()
	sr.CompletedAt = &now
	sr.Status = StepRunStatusSkipped
	sr.SkipReason = reason
}

// Cancel marks the step as canceled.
func (sr *StepRun) Cancel() {
	now := time.Now()
	sr.CompletedAt = &now
	sr.Status = StepRunStatusCanceled
}

// Timeout marks the step as timed out.
func (sr *StepRun) Timeout() {
	now := time.Now()
	sr.CompletedAt = &now
	sr.Status = StepRunStatusTimeout
	sr.ErrorMessage = "step execution timed out"
	sr.ErrorCode = "TIMEOUT"
}

// SetConditionResult sets the condition evaluation result.
func (sr *StepRun) SetConditionResult(result bool) {
	sr.ConditionEvaluated = true
	sr.ConditionResult = &result
}

// ShouldSkip checks if the step should be skipped based on condition.
func (sr *StepRun) ShouldSkip() bool {
	if !sr.ConditionEvaluated {
		return false
	}
	return sr.ConditionResult != nil && !*sr.ConditionResult
}

// CanRetry checks if the step can be retried.
func (sr *StepRun) CanRetry() bool {
	return sr.Status == StepRunStatusFailed && sr.Attempt < sr.MaxAttempts
}

// PrepareRetry prepares the step for retry.
func (sr *StepRun) PrepareRetry() {
	sr.Attempt++
	sr.Status = StepRunStatusPending
	sr.QueuedAt = nil
	sr.StartedAt = nil
	sr.CompletedAt = nil
	sr.SensorID = nil
	sr.CommandID = nil
	sr.ErrorMessage = ""
	sr.ErrorCode = ""
}

// IsRunning checks if the step is running.
func (sr *StepRun) IsRunning() bool {
	return sr.Status == StepRunStatusRunning
}

// IsPending checks if the step is pending.
func (sr *StepRun) IsPending() bool {
	return sr.Status == StepRunStatusPending
}

// IsQueued checks if the step is queued.
func (sr *StepRun) IsQueued() bool {
	return sr.Status == StepRunStatusQueued
}

// IsComplete checks if the step is complete (terminal state).
func (sr *StepRun) IsComplete() bool {
	return sr.Status.IsTerminal()
}

// IsSuccess checks if the step completed successfully.
func (sr *StepRun) IsSuccess() bool {
	return sr.Status.IsSuccess()
}

// Duration returns the duration of the step execution.
func (sr *StepRun) Duration() time.Duration {
	if sr.StartedAt == nil {
		return 0
	}
	end := time.Now()
	if sr.CompletedAt != nil {
		end = *sr.CompletedAt
	}
	return end.Sub(*sr.StartedAt)
}

// WaitTime returns the time spent waiting in queue.
func (sr *StepRun) WaitTime() time.Duration {
	if sr.QueuedAt == nil {
		return 0
	}
	start := time.Now()
	if sr.StartedAt != nil {
		start = *sr.StartedAt
	}
	return start.Sub(*sr.QueuedAt)
}
