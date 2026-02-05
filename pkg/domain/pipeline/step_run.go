package pipeline

import (
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// StepRunStatus represents the status of a step run.
type StepRunStatus string

const (
	StepRunStatusPending   StepRunStatus = "pending"
	StepRunStatusQueued    StepRunStatus = "queued"
	StepRunStatusRunning   StepRunStatus = "running"
	StepRunStatusCompleted StepRunStatus = "completed"
	StepRunStatusFailed    StepRunStatus = "failed"
	StepRunStatusSkipped   StepRunStatus = "skipped"
	StepRunStatusCanceled  StepRunStatus = "canceled"
	StepRunStatusTimeout   StepRunStatus = "timeout"
)

// IsValid checks if the step run status is valid.
func (s StepRunStatus) IsValid() bool {
	switch s {
	case StepRunStatusPending, StepRunStatusQueued, StepRunStatusRunning,
		StepRunStatusCompleted, StepRunStatusFailed, StepRunStatusSkipped,
		StepRunStatusCanceled, StepRunStatusTimeout:
		return true
	}
	return false
}

// IsTerminal checks if the status is terminal.
func (s StepRunStatus) IsTerminal() bool {
	switch s {
	case StepRunStatusCompleted, StepRunStatusFailed, StepRunStatusSkipped,
		StepRunStatusCanceled, StepRunStatusTimeout:
		return true
	}
	return false
}

// IsSuccess checks if the status indicates success.
func (s StepRunStatus) IsSuccess() bool {
	return s == StepRunStatusCompleted
}

// StepRun represents an execution of a pipeline step.
type StepRun struct {
	ID            shared.ID
	PipelineRunID shared.ID
	StepID        shared.ID

	// Step identification
	StepKey   string
	StepOrder int

	// Execution
	Status StepRunStatus

	// Agent assignment
	AgentID   *shared.ID
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

// Queue marks the step as queued for execution.
func (sr *StepRun) Queue() {
	now := time.Now()
	sr.QueuedAt = &now
	sr.Status = StepRunStatusQueued
}

// Start marks the step as started.
func (sr *StepRun) Start(agentID, commandID shared.ID) {
	now := time.Now()
	sr.StartedAt = &now
	sr.Status = StepRunStatusRunning
	sr.AgentID = &agentID
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
	sr.AgentID = nil
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
