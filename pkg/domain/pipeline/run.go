package pipeline

import (
	"time"

	"github.com/openctemio/api/pkg/domain/scanprofile"
	"github.com/openctemio/api/pkg/domain/shared"
)

// RunStatus represents the status of a pipeline run.
type RunStatus string

const (
	RunStatusPending   RunStatus = "pending"
	RunStatusRunning   RunStatus = "running"
	RunStatusCompleted RunStatus = "completed"
	RunStatusFailed    RunStatus = "failed"
	RunStatusCanceled  RunStatus = "canceled"
	RunStatusTimeout   RunStatus = "timeout"
)

// IsValid checks if the run status is valid.
func (s RunStatus) IsValid() bool {
	switch s {
	case RunStatusPending, RunStatusRunning, RunStatusCompleted, RunStatusFailed, RunStatusCanceled, RunStatusTimeout:
		return true
	}
	return false
}

// IsTerminal checks if the status is terminal (no more state changes).
func (s RunStatus) IsTerminal() bool {
	switch s {
	case RunStatusCompleted, RunStatusFailed, RunStatusCanceled, RunStatusTimeout:
		return true
	}
	return false
}

// Run represents an execution of a pipeline.
type Run struct {
	ID         shared.ID
	PipelineID shared.ID
	TenantID   shared.ID
	AssetID    *shared.ID
	ScanID     *shared.ID // Reference to the scan that triggered this run

	// Trigger info
	TriggerType TriggerType
	TriggeredBy string // User email, system, webhook name, etc.

	// Status
	Status RunStatus

	// Context (inputs for the pipeline)
	Context map[string]any

	// Results summary
	TotalSteps     int
	CompletedSteps int
	FailedSteps    int
	SkippedSteps   int
	TotalFindings  int

	// Timing
	StartedAt   *time.Time
	CompletedAt *time.Time

	// Error info
	ErrorMessage string

	// Scan Profile and Quality Gate
	ScanProfileID     *shared.ID                     // Reference to the scan profile used
	QualityGateResult *scanprofile.QualityGateResult // Quality gate evaluation result

	// Step runs (loaded separately)
	StepRuns []*StepRun

	// Timestamps
	CreatedAt time.Time
}

// NewRun creates a new pipeline run.
func NewRun(
	pipelineID shared.ID,
	tenantID shared.ID,
	assetID *shared.ID,
	triggerType TriggerType,
	triggeredBy string,
	context map[string]any,
) (*Run, error) {
	if context == nil {
		context = make(map[string]any)
	}

	return &Run{
		ID:          shared.NewID(),
		PipelineID:  pipelineID,
		TenantID:    tenantID,
		AssetID:     assetID,
		TriggerType: triggerType,
		TriggeredBy: triggeredBy,
		Status:      RunStatusPending,
		Context:     context,
		StepRuns:    []*StepRun{},
		CreatedAt:   time.Now(),
	}, nil
}

// Start starts the pipeline run.
func (r *Run) Start() {
	now := time.Now()
	r.StartedAt = &now
	r.Status = RunStatusRunning
}

// Complete marks the run as completed.
func (r *Run) Complete() {
	now := time.Now()
	r.CompletedAt = &now
	r.Status = RunStatusCompleted
}

// Fail marks the run as failed.
func (r *Run) Fail(message string) {
	now := time.Now()
	r.CompletedAt = &now
	r.Status = RunStatusFailed
	r.ErrorMessage = message
}

// Cancel cancels the run.
func (r *Run) Cancel() {
	now := time.Now()
	r.CompletedAt = &now
	r.Status = RunStatusCanceled
}

// Timeout marks the run as timed out.
func (r *Run) Timeout() {
	now := time.Now()
	r.CompletedAt = &now
	r.Status = RunStatusTimeout
}

// UpdateStats updates the run statistics.
func (r *Run) UpdateStats(completed, failed, skipped, findings int) {
	r.CompletedSteps = completed
	r.FailedSteps = failed
	r.SkippedSteps = skipped
	r.TotalFindings = findings
}

// SetTotalSteps sets the total number of steps.
func (r *Run) SetTotalSteps(total int) {
	r.TotalSteps = total
}

// AddStepRun adds a step run.
func (r *Run) AddStepRun(stepRun *StepRun) {
	r.StepRuns = append(r.StepRuns, stepRun)
}

// GetStepRun returns a step run by step key.
func (r *Run) GetStepRun(stepKey string) *StepRun {
	for _, sr := range r.StepRuns {
		if sr.StepKey == stepKey {
			return sr
		}
	}
	return nil
}

// IsRunning checks if the run is still running.
func (r *Run) IsRunning() bool {
	return r.Status == RunStatusRunning
}

// IsPending checks if the run is pending.
func (r *Run) IsPending() bool {
	return r.Status == RunStatusPending
}

// IsComplete checks if the run is complete (terminal state).
func (r *Run) IsComplete() bool {
	return r.Status.IsTerminal()
}

// HasFailedSteps checks if any steps failed.
func (r *Run) HasFailedSteps() bool {
	return r.FailedSteps > 0
}

// GetProgress returns the progress percentage.
func (r *Run) GetProgress() int {
	if r.TotalSteps == 0 {
		return 0
	}
	completed := r.CompletedSteps + r.FailedSteps + r.SkippedSteps
	return (completed * 100) / r.TotalSteps
}

// Duration returns the duration of the run.
func (r *Run) Duration() time.Duration {
	if r.StartedAt == nil {
		return 0
	}
	end := time.Now()
	if r.CompletedAt != nil {
		end = *r.CompletedAt
	}
	return end.Sub(*r.StartedAt)
}

// SetScanProfile links this run to a scan profile.
func (r *Run) SetScanProfile(profileID shared.ID) {
	r.ScanProfileID = &profileID
}

// SetQualityGateResult stores the quality gate evaluation result.
func (r *Run) SetQualityGateResult(result *scanprofile.QualityGateResult) {
	r.QualityGateResult = result
}

// QualityGatePassed returns true if quality gate passed or was not evaluated.
func (r *Run) QualityGatePassed() bool {
	if r.QualityGateResult == nil {
		return true // No QG = pass
	}
	return r.QualityGateResult.Passed
}
