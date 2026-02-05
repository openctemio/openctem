package workflow

import (
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// RunStatus represents the status of a workflow run.
type RunStatus string

const (
	RunStatusPending   RunStatus = "pending"
	RunStatusRunning   RunStatus = "running"
	RunStatusCompleted RunStatus = "completed"
	RunStatusFailed    RunStatus = "failed"
	RunStatusCancelled RunStatus = "cancelled"
)

// IsValid checks if the run status is valid.
func (s RunStatus) IsValid() bool {
	switch s {
	case RunStatusPending, RunStatusRunning, RunStatusCompleted, RunStatusFailed, RunStatusCancelled:
		return true
	}
	return false
}

// IsTerminal checks if the status is a terminal state.
func (s RunStatus) IsTerminal() bool {
	return s == RunStatusCompleted || s == RunStatusFailed || s == RunStatusCancelled
}

// Run represents an execution of a workflow.
type Run struct {
	ID         shared.ID
	WorkflowID shared.ID
	TenantID   shared.ID

	// Trigger information
	TriggerType TriggerType
	TriggerData map[string]any

	// Status
	Status       RunStatus
	ErrorMessage string

	// Context data passed through the workflow
	Context map[string]any

	// Statistics
	TotalNodes     int
	CompletedNodes int
	FailedNodes    int

	// Node runs (loaded separately)
	NodeRuns []*NodeRun

	// Timing
	StartedAt   *time.Time
	CompletedAt *time.Time

	// Audit
	TriggeredBy *shared.ID
	CreatedAt   time.Time
}

// NewRun creates a new workflow run.
func NewRun(
	workflowID shared.ID,
	tenantID shared.ID,
	triggerType TriggerType,
	triggerData map[string]any,
) (*Run, error) {
	if workflowID.IsZero() {
		return nil, shared.NewDomainError("VALIDATION", "workflow_id is required", shared.ErrValidation)
	}
	if tenantID.IsZero() {
		return nil, shared.NewDomainError("VALIDATION", "tenant_id is required", shared.ErrValidation)
	}

	now := time.Now()
	return &Run{
		ID:          shared.NewID(),
		WorkflowID:  workflowID,
		TenantID:    tenantID,
		TriggerType: triggerType,
		TriggerData: triggerData,
		Status:      RunStatusPending,
		Context:     make(map[string]any),
		NodeRuns:    []*NodeRun{},
		CreatedAt:   now,
	}, nil
}

// Start marks the run as started.
func (r *Run) Start() {
	now := time.Now()
	r.Status = RunStatusRunning
	r.StartedAt = &now
}

// Complete marks the run as completed.
func (r *Run) Complete() {
	now := time.Now()
	r.Status = RunStatusCompleted
	r.CompletedAt = &now
}

// Fail marks the run as failed.
func (r *Run) Fail(errorMessage string) {
	now := time.Now()
	r.Status = RunStatusFailed
	r.ErrorMessage = errorMessage
	r.CompletedAt = &now
}

// Cancel marks the run as cancelled.
func (r *Run) Cancel() {
	now := time.Now()
	r.Status = RunStatusCancelled
	r.CompletedAt = &now
}

// SetTriggeredBy sets the user who triggered the run.
func (r *Run) SetTriggeredBy(userID shared.ID) {
	r.TriggeredBy = &userID
}

// SetContext sets the workflow context data.
func (r *Run) SetContext(ctx map[string]any) {
	r.Context = ctx
}

// AddToContext adds a value to the workflow context.
func (r *Run) AddToContext(key string, value any) {
	if r.Context == nil {
		r.Context = make(map[string]any)
	}
	r.Context[key] = value
}

// SetStats sets the run statistics.
func (r *Run) SetStats(total, completed, failed int) {
	r.TotalNodes = total
	r.CompletedNodes = completed
	r.FailedNodes = failed
}

// Duration returns the run duration.
func (r *Run) Duration() time.Duration {
	if r.StartedAt == nil {
		return 0
	}
	if r.CompletedAt != nil {
		return r.CompletedAt.Sub(*r.StartedAt)
	}
	return time.Since(*r.StartedAt)
}
