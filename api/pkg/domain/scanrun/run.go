package scanrun

import (
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/openctemio/openctem/api/pkg/domain/scanprofile"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RunStatus represents the status of a scan run.
type RunStatus string

const (
	RunStatusPending   RunStatus = "pending"
	RunStatusRunning   RunStatus = "running"
	RunStatusCompleted RunStatus = "completed"
	// RunStatusPartial: the run kept results but lost some work (a step or a
	// batch failed while others completed). Terminal; never retried as a
	// whole (RFC-046 D5).
	RunStatusPartial  RunStatus = "partial"
	RunStatusFailed   RunStatus = "failed"
	RunStatusCanceled RunStatus = "canceled"
	RunStatusTimeout  RunStatus = "timeout"
	// RunStatusBlocked: the trigger was refused before anything was
	// dispatched (scope gate, freeze window, unavailable tool or sensor, no
	// target). Terminal and never retried; RefusalCode says why.
	RunStatusBlocked RunStatus = "blocked"
)

// IsValid checks if the run status is valid.
func (s RunStatus) IsValid() bool {
	switch s {
	case RunStatusPending, RunStatusRunning, RunStatusCompleted, RunStatusPartial, RunStatusFailed, RunStatusCanceled, RunStatusTimeout, RunStatusBlocked:
		return true
	}
	return false
}

// IsTerminal checks if the status is terminal (no more state changes).
func (s RunStatus) IsTerminal() bool {
	switch s {
	case RunStatusCompleted, RunStatusPartial, RunStatusFailed, RunStatusCanceled, RunStatusTimeout, RunStatusBlocked:
		return true
	}
	return false
}

// ErrRunAlreadyFinished is returned when a write would move a run that already
// reached a terminal state (completed, partial, failed, canceled, timeout). A terminal
// run is final: a late sensor result, a cancel racing a completion, or a stale
// in-memory copy must not reopen it or record its outcome a second time.
var ErrRunAlreadyFinished = shared.NewDomainError("RUN_ALREADY_FINISHED",
	"pipeline run has already finished", shared.ErrConflict)

// ErrScanRunActive is returned when a scheduled run is created while the
// scan already has an active run (overlap policy skip, RFC-046 D4). The check
// runs under the scan row lock that serializes every trigger of the scan, in
// the transaction that inserts the run (§6.2), so a manual trigger cannot
// slip in between the check and the insert.
var ErrScanRunActive = shared.NewDomainError("SCAN_RUN_IN_PROGRESS",
	"the scan's previous run is still active", shared.ErrConflict)

// ErrOccurrenceAlreadyRun is returned when a run is created for a schedule
// occurrence of a scan that already has a run: a second scheduler instance,
// or a retried trigger, firing the same slot.
var ErrOccurrenceAlreadyRun = shared.NewDomainError("OCCURRENCE_ALREADY_RUN",
	"this schedule occurrence of the scan already has a run", shared.ErrConflict)

// Run represents an execution of a scan workflow.
type Run struct {
	ID             shared.ID
	ScanWorkflowID shared.ID
	TenantID       shared.ID
	AssetID        *shared.ID
	ScanID         *shared.ID // Reference to the scan that triggered this run

	// Trigger info
	TriggerType scanworkflow.TriggerType
	TriggeredBy string // User email, system, webhook name, etc.

	// Status
	Status RunStatus

	// Context (inputs for the scan workflow)
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
	// RefusalCode is the machine-readable reason of a blocked run: the
	// domain error code of the refused trigger (e.g. ALL_TARGETS_EXCLUDED).
	RefusalCode string

	// Scan Profile and Quality Gate
	ScanProfileID     *shared.ID                     // Reference to the scan profile used
	QualityGateResult *scanprofile.QualityGateResult // Quality gate evaluation result

	// Retry tracking
	RetryAttempt int // 0 = first attempt, N = Nth retry

	// ScheduledFor is the schedule occurrence this run serves (nil for a run
	// that was not started by the scheduler). A scan has at most one run per
	// occurrence: UNIQUE(scan_id, scheduled_for).
	ScheduledFor *time.Time

	// FreezeOverride: a member with scans:freeze:override started this run
	// while a scan freeze window was active (audited). Its commands carry
	// the override, so the claim-time freeze hold lets them through.
	FreezeOverride bool

	// DeadlineAt is when the reaper settles the run if it is still open:
	// started_at plus the scan timeout, capped at 24 h, fixed when the run
	// starts (RFC-046 §6.3). Nil for runs started before migration 000674.
	DeadlineAt *time.Time

	// UnfinishedTargetCount is how many targets were still open when the run
	// was settled at its deadline. The targets themselves are read with
	// RolloverStore.GetUnfinishedTargets.
	UnfinishedTargetCount int

	// Kind is what the run is (RunKindScan for a scan's run). A run that
	// executes no scan workflow (a retest) has a zero ScanWorkflowID and
	// names what it is about in Subject.
	Kind    RunKind
	Subject map[string]any

	// Step runs (loaded separately)
	StepRuns []*StepRun

	// Timestamps
	CreatedAt time.Time
}

// NewRun creates a new scan run.
func NewRun(
	scanWorkflowID shared.ID,
	tenantID shared.ID,
	assetID *shared.ID,
	triggerType scanworkflow.TriggerType,
	triggeredBy string,
	context map[string]any,
) (*Run, error) {
	if context == nil {
		context = make(map[string]any)
	}

	return &Run{
		ID:             shared.NewID(),
		ScanWorkflowID: scanWorkflowID,
		TenantID:       tenantID,
		AssetID:        assetID,
		TriggerType:    triggerType,
		TriggeredBy:    triggeredBy,
		Status:         RunStatusPending,
		Context:        context,
		StepRuns:       []*StepRun{},
		CreatedAt:      time.Now(),
	}, nil
}

// Start starts the scan run.
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

// Block records a trigger that was refused before anything was dispatched:
// the run is terminal at once, with the refusal's code and message.
func (r *Run) Block(code, message string) {
	now := time.Now()
	r.CompletedAt = &now
	r.Status = RunStatusBlocked
	r.RefusalCode = code
	r.ErrorMessage = message
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

// ContextValue returns a value of the run context, or nil.
func (r *Run) ContextValue(key string) any {
	return r.Context[key]
}

// StepSucceeded reports whether the step run of stepKey succeeded.
func (r *Run) StepSucceeded(stepKey string) bool {
	sr := r.GetStepRun(stepKey)
	return sr != nil && sr.IsSuccess()
}

// StepFinishedWithoutResults reports whether the step run of stepKey finished
// without producing results. A partial step run produced results.
func (r *Run) StepFinishedWithoutResults(stepKey string) bool {
	sr := r.GetStepRun(stepKey)
	return sr != nil && sr.IsComplete() && !sr.Status.ProducedResults()
}

// RunKind says what a run is (research/62 §4.3). Every unit of sensor work
// belongs to one run, so retests and other non-scan work show up in Runs.
type RunKind string

const (
	RunKindScan       RunKind = "scan"
	RunKindQuick      RunKind = "quick"
	RunKindRetest     RunKind = "retest"
	RunKindValidation RunKind = "validation"
	RunKindTest       RunKind = "test"
	RunKindConnector  RunKind = "connector"
	// RunKindSystem is platform housekeeping; the Runs list hides it unless
	// asked.
	RunKindSystem RunKind = "system"
)

// IsValid reports whether k is a known run kind.
func (k RunKind) IsValid() bool {
	switch k {
	case RunKindScan, RunKindQuick, RunKindRetest, RunKindValidation, RunKindTest, RunKindConnector, RunKindSystem:
		return true
	}
	return false
}

// KindOrDefault is the run's kind, RunKindScan when unset.
func (r *Run) KindOrDefault() RunKind {
	if r.Kind == "" {
		return RunKindScan
	}
	return r.Kind
}
