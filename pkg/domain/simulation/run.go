package simulation

import (
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// SimulationRun represents a single execution of a simulation.
type SimulationRun struct {
	id               shared.ID
	tenantID         shared.ID
	simulationID     shared.ID
	status           RunStatus
	result           RunResult
	detectionResult  string
	preventionResult string
	steps            []map[string]any
	output           map[string]any
	errorMessage     string
	startedAt        *time.Time
	completedAt      *time.Time
	durationMs       int
	triggeredBy      *shared.ID
	createdAt        time.Time
}

// NewSimulationRun creates a new run for a simulation.
func NewSimulationRun(tenantID, simulationID shared.ID) *SimulationRun {
	return &SimulationRun{
		id:           shared.NewID(),
		tenantID:     tenantID,
		simulationID: simulationID,
		status:       RunStatusPending,
		steps:        []map[string]any{},
		output:       map[string]any{},
		createdAt:    time.Now(),
	}
}

// ReconstituteRun creates a run from persisted data.
func ReconstituteRun(
	id, tenantID, simulationID shared.ID,
	status RunStatus, result RunResult,
	detectionResult, preventionResult string,
	steps []map[string]any, output map[string]any,
	errorMessage string,
	startedAt, completedAt *time.Time, durationMs int,
	triggeredBy *shared.ID, createdAt time.Time,
) *SimulationRun {
	return &SimulationRun{
		id: id, tenantID: tenantID, simulationID: simulationID,
		status: status, result: result,
		detectionResult: detectionResult, preventionResult: preventionResult,
		steps: steps, output: output, errorMessage: errorMessage,
		startedAt: startedAt, completedAt: completedAt, durationMs: durationMs,
		triggeredBy: triggeredBy, createdAt: createdAt,
	}
}

// Getters
func (r *SimulationRun) ID() shared.ID           { return r.id }
func (r *SimulationRun) TenantID() shared.ID      { return r.tenantID }
func (r *SimulationRun) SimulationID() shared.ID   { return r.simulationID }
func (r *SimulationRun) Status() RunStatus         { return r.status }
func (r *SimulationRun) Result() RunResult         { return r.result }
func (r *SimulationRun) DetectionResult() string   { return r.detectionResult }
func (r *SimulationRun) PreventionResult() string  { return r.preventionResult }
func (r *SimulationRun) Steps() []map[string]any   { return r.steps }
func (r *SimulationRun) Output() map[string]any    { return r.output }
func (r *SimulationRun) ErrorMessage() string      { return r.errorMessage }
func (r *SimulationRun) StartedAt() *time.Time     { return r.startedAt }
func (r *SimulationRun) CompletedAt() *time.Time   { return r.completedAt }
func (r *SimulationRun) DurationMs() int           { return r.durationMs }
func (r *SimulationRun) TriggeredBy() *shared.ID   { return r.triggeredBy }
func (r *SimulationRun) CreatedAt() time.Time      { return r.createdAt }

// Start marks the run as started.
func (r *SimulationRun) Start() {
	now := time.Now()
	r.status = RunStatusRunning
	r.startedAt = &now
}

// Complete marks the run as completed with results.
func (r *SimulationRun) Complete(result RunResult, detection, prevention string, output map[string]any) {
	now := time.Now()
	r.status = RunStatusCompleted
	r.result = result
	r.detectionResult = detection
	r.preventionResult = prevention
	r.output = output
	r.completedAt = &now
	if r.startedAt != nil {
		r.durationMs = int(now.Sub(*r.startedAt).Milliseconds())
	}
}

// Fail marks the run as failed.
func (r *SimulationRun) Fail(errMsg string) {
	now := time.Now()
	r.status = RunStatusFailed
	r.result = RunResultError
	r.errorMessage = errMsg
	r.completedAt = &now
	if r.startedAt != nil {
		r.durationMs = int(now.Sub(*r.startedAt).Milliseconds())
	}
}

// SetTriggeredBy sets who triggered the run.
func (r *SimulationRun) SetTriggeredBy(userID shared.ID) {
	r.triggeredBy = &userID
}
