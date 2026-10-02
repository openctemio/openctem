// Package simulation provides domain models for Breach and Attack Simulation (BAS).
package simulation

import (
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// SimulationType defines the kind of simulation.
type SimulationType string

const (
	SimulationTypeAtomic      SimulationType = "atomic"
	SimulationTypeCampaign    SimulationType = "campaign"
	SimulationTypeControlTest SimulationType = "control_test"
)

// SimulationStatus defines lifecycle states.
type SimulationStatus string

const (
	SimulationStatusDraft     SimulationStatus = "draft"
	SimulationStatusActive    SimulationStatus = "active"
	SimulationStatusPaused    SimulationStatus = "paused"
	SimulationStatusCompleted SimulationStatus = "completed"
	SimulationStatusArchived  SimulationStatus = "archived"
)

// RunStatus defines execution states.
type RunStatus string

const (
	RunStatusPending   RunStatus = "pending"
	RunStatusRunning   RunStatus = "running"
	RunStatusCompleted RunStatus = "completed"
	RunStatusFailed    RunStatus = "failed"
)

// RunResult defines outcome of a simulation run.
type RunResult string

const (
	RunResultDetected  RunResult = "detected"
	RunResultPrevented RunResult = "prevented"
	RunResultBypassed  RunResult = "bypassed"
	RunResultPartial   RunResult = "partial"
	RunResultError     RunResult = "error"
)

// Simulation represents an attack simulation definition.
type Simulation struct {
	id                 shared.ID
	tenantID           shared.ID
	name               string
	description        string
	simulationType     SimulationType
	status             SimulationStatus
	mitreTactic        string
	mitreTechniqueID   string
	mitreTechniqueName string
	targetAssets       []string
	config             map[string]any
	scheduleCron       string
	lastRunAt          *time.Time
	nextRunAt          *time.Time
	totalRuns          int
	lastResult         string
	detectionRate      float64
	preventionRate     float64
	tags               []string
	createdBy          *shared.ID
	createdAt          time.Time
	updatedAt          time.Time
}

// NewSimulation creates a new simulation.
func NewSimulation(tenantID shared.ID, name string, simType SimulationType) (*Simulation, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	now := time.Now()
	return &Simulation{
		id:             shared.NewID(),
		tenantID:       tenantID,
		name:           name,
		simulationType: simType,
		status:         SimulationStatusDraft,
		targetAssets:   []string{},
		config:         map[string]any{},
		tags:           []string{},
		createdAt:      now,
		updatedAt:      now,
	}, nil
}

// ReconstituteSimulation creates a Simulation from persisted data.
func ReconstituteSimulation(
	id, tenantID shared.ID,
	name, description string,
	simType SimulationType, status SimulationStatus,
	mitreTactic, mitreTechniqueID, mitreTechniqueName string,
	targetAssets []string, config map[string]any,
	scheduleCron string, lastRunAt, nextRunAt *time.Time,
	totalRuns int, lastResult string,
	detectionRate, preventionRate float64,
	tags []string, createdBy *shared.ID,
	createdAt, updatedAt time.Time,
) *Simulation {
	return &Simulation{
		id: id, tenantID: tenantID,
		name: name, description: description,
		simulationType: simType, status: status,
		mitreTactic: mitreTactic, mitreTechniqueID: mitreTechniqueID, mitreTechniqueName: mitreTechniqueName,
		targetAssets: targetAssets, config: config,
		scheduleCron: scheduleCron, lastRunAt: lastRunAt, nextRunAt: nextRunAt,
		totalRuns: totalRuns, lastResult: lastResult,
		detectionRate: detectionRate, preventionRate: preventionRate,
		tags: tags, createdBy: createdBy,
		createdAt: createdAt, updatedAt: updatedAt,
	}
}

// Getters
func (s *Simulation) ID() shared.ID             { return s.id }
func (s *Simulation) TenantID() shared.ID        { return s.tenantID }
func (s *Simulation) Name() string               { return s.name }
func (s *Simulation) Description() string         { return s.description }
func (s *Simulation) SimulationType() SimulationType { return s.simulationType }
func (s *Simulation) Status() SimulationStatus    { return s.status }
func (s *Simulation) MitreTactic() string         { return s.mitreTactic }
func (s *Simulation) MitreTechniqueID() string    { return s.mitreTechniqueID }
func (s *Simulation) MitreTechniqueName() string  { return s.mitreTechniqueName }
func (s *Simulation) TargetAssets() []string       { return s.targetAssets }
func (s *Simulation) Config() map[string]any       { return s.config }
func (s *Simulation) ScheduleCron() string         { return s.scheduleCron }
func (s *Simulation) LastRunAt() *time.Time        { return s.lastRunAt }
func (s *Simulation) NextRunAt() *time.Time        { return s.nextRunAt }
func (s *Simulation) TotalRuns() int               { return s.totalRuns }
func (s *Simulation) LastResult() string           { return s.lastResult }
func (s *Simulation) DetectionRate() float64       { return s.detectionRate }
func (s *Simulation) PreventionRate() float64      { return s.preventionRate }
func (s *Simulation) Tags() []string               { return s.tags }
func (s *Simulation) CreatedBy() *shared.ID        { return s.createdBy }
func (s *Simulation) CreatedAt() time.Time         { return s.createdAt }
func (s *Simulation) UpdatedAt() time.Time         { return s.updatedAt }

// Update sets mutable fields.
func (s *Simulation) Update(name, description string) {
	if name != "" {
		s.name = name
	}
	s.description = description
	s.updatedAt = time.Now()
}

// SetMITRE sets ATT&CK mapping.
func (s *Simulation) SetMITRE(tactic, techniqueID, techniqueName string) {
	s.mitreTactic = tactic
	s.mitreTechniqueID = techniqueID
	s.mitreTechniqueName = techniqueName
	s.updatedAt = time.Now()
}

// allowedConfigKeys defines the whitelist of valid config keys to prevent injection.
var allowedConfigKeys = map[string]bool{
	"timeout":          true,
	"target_asset_ids": true,
	"technique_params": true,
	"detection_source": true,
	"schedule_type":    true,
	"notify_on_result": true,
	"max_retries":      true,
	"dry_run":          true,
}

// SetConfig sets simulation configuration after validating allowed keys.
func (s *Simulation) SetConfig(config map[string]any, targetAssets, tags []string) error {
	for k := range config {
		if !allowedConfigKeys[k] {
			return fmt.Errorf("%w: invalid config key: %s", shared.ErrValidation, k)
		}
	}
	s.config = config
	s.targetAssets = targetAssets
	s.tags = tags
	s.updatedAt = time.Now()
	return nil
}

// SetSchedule sets cron schedule.
func (s *Simulation) SetSchedule(cron string) {
	s.scheduleCron = cron
	s.updatedAt = time.Now()
}

// RecordRun updates run statistics after a simulation run completes.
func (s *Simulation) RecordRun(result string, detectionRate, preventionRate float64) {
	now := time.Now()
	s.totalRuns++
	s.lastResult = result
	s.lastRunAt = &now
	s.detectionRate = detectionRate
	s.preventionRate = preventionRate
	s.updatedAt = now
}

// Activate transitions simulation to active.
func (s *Simulation) Activate() error {
	if s.status != SimulationStatusDraft && s.status != SimulationStatusPaused {
		return fmt.Errorf("%w: cannot activate from %s", shared.ErrValidation, s.status)
	}
	s.status = SimulationStatusActive
	s.updatedAt = time.Now()
	return nil
}

// SetCreatedBy sets the creator.
func (s *Simulation) SetCreatedBy(userID shared.ID) {
	s.createdBy = &userID
}
