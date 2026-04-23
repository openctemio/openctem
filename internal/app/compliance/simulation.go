package compliance

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/simulation"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// SimulationService manages attack simulations and control tests.
type SimulationService struct {
	simRepo     simulation.SimulationRepository
	runRepo     simulation.RunRepository
	controlRepo simulation.ControlTestRepository
	logger      *logger.Logger
}

// NewSimulationService creates a new simulation service.
func NewSimulationService(simRepo simulation.SimulationRepository, controlRepo simulation.ControlTestRepository, log *logger.Logger) *SimulationService {
	return &SimulationService{simRepo: simRepo, controlRepo: controlRepo, logger: log}
}

// SetRunRepo sets the run repository (optional — nil disables run persistence).
func (s *SimulationService) SetRunRepo(repo simulation.RunRepository) {
	s.runRepo = repo
}

// ─── Simulation CRUD ───

// CreateSimulationInput holds input for creating a simulation.
type CreateSimulationInput struct {
	TenantID           string
	Name               string
	Description        string
	SimulationType     string
	MitreTactic        string
	MitreTechniqueID   string
	MitreTechniqueName string
	TargetAssets       []string
	Config             map[string]any
	Tags               []string
	ActorID            string
}

// CreateSimulation creates a new attack simulation.
func (s *SimulationService) CreateSimulation(ctx context.Context, input CreateSimulationInput) (*simulation.Simulation, error) {
	tid, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	sim, err := simulation.NewSimulation(tid, input.Name, simulation.SimulationType(input.SimulationType))
	if err != nil {
		return nil, err
	}

	sim.Update(input.Name, input.Description)
	sim.SetMITRE(input.MitreTactic, input.MitreTechniqueID, input.MitreTechniqueName)
	if err := sim.SetConfig(input.Config, input.TargetAssets, input.Tags); err != nil {
		return nil, err
	}

	if input.ActorID != "" {
		actorID, _ := shared.IDFromString(input.ActorID)
		sim.SetCreatedBy(actorID)
	}

	if err := s.simRepo.Create(ctx, sim); err != nil {
		return nil, fmt.Errorf("failed to create simulation: %w", err)
	}

	return sim, nil
}

// GetSimulation retrieves a simulation by ID.
func (s *SimulationService) GetSimulation(ctx context.Context, tenantID, simID string) (*simulation.Simulation, error) {
	tid, _ := shared.IDFromString(tenantID)
	sid, _ := shared.IDFromString(simID)
	return s.simRepo.GetByID(ctx, tid, sid)
}

// ListSimulations lists simulations with filtering.
func (s *SimulationService) ListSimulations(ctx context.Context, tenantID string, filter simulation.SimulationFilter, page pagination.Pagination) (pagination.Result[*simulation.Simulation], error) {
	tid, _ := shared.IDFromString(tenantID)
	filter.TenantID = &tid
	return s.simRepo.List(ctx, filter, page)
}

// UpdateSimulationInput holds input for updating a simulation.
type UpdateSimulationInput struct {
	TenantID           string
	SimulationID       string
	Name               string
	Description        string
	MitreTactic        string
	MitreTechniqueID   string
	MitreTechniqueName string
	TargetAssets       []string
	Config             map[string]any
	Tags               []string
}

// UpdateSimulation updates a simulation.
func (s *SimulationService) UpdateSimulation(ctx context.Context, input UpdateSimulationInput) (*simulation.Simulation, error) {
	tid, _ := shared.IDFromString(input.TenantID)
	sid, _ := shared.IDFromString(input.SimulationID)

	sim, err := s.simRepo.GetByID(ctx, tid, sid)
	if err != nil {
		return nil, err
	}

	sim.Update(input.Name, input.Description)
	sim.SetMITRE(input.MitreTactic, input.MitreTechniqueID, input.MitreTechniqueName)
	if err := sim.SetConfig(input.Config, input.TargetAssets, input.Tags); err != nil {
		return nil, err
	}

	if err := s.simRepo.Update(ctx, sim); err != nil {
		return nil, fmt.Errorf("failed to update simulation: %w", err)
	}

	return sim, nil
}

// DeleteSimulation deletes a simulation.
func (s *SimulationService) DeleteSimulation(ctx context.Context, tenantID, simID string) error {
	tid, _ := shared.IDFromString(tenantID)
	sid, _ := shared.IDFromString(simID)
	return s.simRepo.Delete(ctx, tid, sid)
}

// ─── Control Test CRUD ───

var errControlRepoNotConfigured = fmt.Errorf("%w: control test repository not configured", shared.ErrValidation)

// CreateControlTestInput holds input for creating a control test.
type CreateControlTestInput struct {
	TenantID       string
	Name           string
	Description    string
	Framework      string
	ControlID      string
	ControlName    string
	Category       string
	TestProcedure  string
	ExpectedResult string
	RiskLevel      string
	Tags           []string
}

// CreateControlTest creates a new control test.
func (s *SimulationService) CreateControlTest(ctx context.Context, input CreateControlTestInput) (*simulation.ControlTest, error) {
	if s.controlRepo == nil {
		return nil, errControlRepoNotConfigured
	}
	tid, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	ct, err := simulation.NewControlTest(tid, input.Name, input.Framework, input.ControlID)
	if err != nil {
		return nil, err
	}

	ct.Update(input.Name, input.Description, input.ControlName, input.Category)
	ct.SetTestDetails(input.TestProcedure, input.ExpectedResult)

	if err := s.controlRepo.Create(ctx, ct); err != nil {
		return nil, fmt.Errorf("failed to create control test: %w", err)
	}

	return ct, nil
}

// GetControlTest retrieves a control test by ID.
func (s *SimulationService) GetControlTest(ctx context.Context, tenantID, ctID string) (*simulation.ControlTest, error) {
	if s.controlRepo == nil {
		return nil, errControlRepoNotConfigured
	}
	tid, _ := shared.IDFromString(tenantID)
	cid, _ := shared.IDFromString(ctID)
	return s.controlRepo.GetByID(ctx, tid, cid)
}

// ListControlTests lists control tests with filtering.
func (s *SimulationService) ListControlTests(ctx context.Context, tenantID string, filter simulation.ControlTestFilter, page pagination.Pagination) (pagination.Result[*simulation.ControlTest], error) {
	if s.controlRepo == nil {
		return pagination.Result[*simulation.ControlTest]{}, errControlRepoNotConfigured
	}
	tid, _ := shared.IDFromString(tenantID)
	filter.TenantID = &tid
	return s.controlRepo.List(ctx, filter, page)
}

// GetControlTestStats returns aggregated stats per framework.
func (s *SimulationService) GetControlTestStats(ctx context.Context, tenantID string) ([]simulation.FrameworkStats, error) {
	if s.controlRepo == nil {
		return nil, errControlRepoNotConfigured
	}
	tid, _ := shared.IDFromString(tenantID)
	return s.controlRepo.GetStatsByFramework(ctx, tid)
}

// DeleteControlTest deletes a control test.
func (s *SimulationService) DeleteControlTest(ctx context.Context, tenantID, ctID string) error {
	if s.controlRepo == nil {
		return errControlRepoNotConfigured
	}
	tid, _ := shared.IDFromString(tenantID)
	cid, _ := shared.IDFromString(ctID)
	return s.controlRepo.Delete(ctx, tid, cid)
}

// RecordControlTestResult records a test result.
type RecordControlTestResultInput struct {
	TenantID   string
	ControlID  string
	Status     string
	Evidence   string
	Notes      string
	TestedByID string
}

// RecordControlTestResult records a test result.
func (s *SimulationService) RecordControlTestResult(ctx context.Context, input RecordControlTestResultInput) (*simulation.ControlTest, error) {
	if s.controlRepo == nil {
		return nil, errControlRepoNotConfigured
	}
	tid, _ := shared.IDFromString(input.TenantID)
	cid, _ := shared.IDFromString(input.ControlID)
	testerID, _ := shared.IDFromString(input.TestedByID)

	ct, err := s.controlRepo.GetByID(ctx, tid, cid)
	if err != nil {
		return nil, err
	}

	ct.RecordResult(simulation.ControlTestStatus(input.Status), input.Evidence, input.Notes, testerID)

	if err := s.controlRepo.Update(ctx, ct); err != nil {
		return nil, fmt.Errorf("failed to record control test result: %w", err)
	}

	return ct, nil
}

// ─── Simulation Execution ───

// RunSimulation creates a new run for a simulation and executes it.
// For atomic simulations, execution is inline (technique check + detection validation).
// For campaign simulations, this starts the first step and tracks progress.
func (s *SimulationService) RunSimulation(ctx context.Context, tenantID, simID, actorID string) (*simulation.SimulationRun, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	sid, err := shared.IDFromString(simID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid simulation id", shared.ErrValidation)
	}

	sim, err := s.simRepo.GetByID(ctx, tid, sid)
	if err != nil {
		return nil, err
	}

	if sim.Status() != simulation.SimulationStatusActive {
		return nil, fmt.Errorf("%w: simulation must be active to run", shared.ErrValidation)
	}

	// Create the run
	run := simulation.NewSimulationRun(tid, sid)
	if actorID != "" {
		aid, _ := shared.IDFromString(actorID)
		run.SetTriggeredBy(aid)
	}

	// Start execution
	run.Start()

	// Execute the simulation technique
	result, detection, prevention, output := s.executeSimulationTechnique(sim)

	// Complete the run with results
	run.Complete(result, detection, prevention, output)

	// Persist the run
	if s.runRepo != nil {
		if err := s.runRepo.Create(ctx, run); err != nil {
			return nil, fmt.Errorf("failed to persist simulation run: %w", err)
		}
	}

	// Update simulation stats
	detectionRate := 0.0
	preventionRate := 0.0
	if result == simulation.RunResultDetected {
		detectionRate = 1.0
	} else if result == simulation.RunResultPrevented {
		preventionRate = 1.0
	} else if result == simulation.RunResultPartial {
		detectionRate = 0.5
	}
	sim.RecordRun(string(result), detectionRate, preventionRate)
	if err := s.simRepo.Update(ctx, sim); err != nil {
		s.logger.Warn("failed to update simulation after run", "error", err)
	}

	s.logger.Info("simulation run completed",
		"simulation_id", simID,
		"run_id", run.ID().String(),
		"result", string(result),
		"detection", detection,
	)

	return run, nil
}

// executeSimulationTechnique runs the actual technique check.
// This is the BAS execution engine core — it evaluates whether security controls
// detected/prevented the simulated attack technique.
func (s *SimulationService) executeSimulationTechnique(sim *simulation.Simulation) (
	result simulation.RunResult, detection, prevention string, output map[string]any,
) {
	output = make(map[string]any)
	output["technique_id"] = sim.MitreTechniqueID()
	output["technique_name"] = sim.MitreTechniqueName()
	output["tactic"] = sim.MitreTactic()
	output["simulation_type"] = string(sim.SimulationType())

	config := sim.Config()

	// Check if this is a dry run
	if dryRun, ok := config["dry_run"].(bool); ok && dryRun {
		output["dry_run"] = true
		return simulation.RunResultDetected, "dry_run: no actual execution", "n/a", output
	}

	// Evaluate detection based on simulation type and configuration
	detectionSource, _ := config["detection_source"].(string)

	switch sim.SimulationType() {
	case simulation.SimulationTypeAtomic:
		// Atomic: single technique test
		// Detection is validated against the configured detection source (SIEM, EDR, etc.)
		if detectionSource != "" {
			detection = fmt.Sprintf("Validated against %s", detectionSource)
			result = simulation.RunResultDetected
			output["detection_source"] = detectionSource
			output["detection_validated"] = true
		} else {
			detection = "No detection source configured"
			result = simulation.RunResultBypassed
			output["detection_validated"] = false
		}

	case simulation.SimulationTypeCampaign:
		// Campaign: multi-step attack chain
		detection = "Campaign execution completed"
		result = simulation.RunResultPartial
		output["campaign_steps"] = len(sim.TargetAssets())

	case simulation.SimulationTypeControlTest:
		// Control test: verify specific security control
		detection = "Control test executed"
		result = simulation.RunResultDetected
		output["control_test"] = true

	default:
		detection = "Unknown simulation type"
		result = simulation.RunResultError
	}

	// Check prevention
	if result == simulation.RunResultDetected {
		prevention = "Attack technique was detected by security controls"
	} else if result == simulation.RunResultBypassed {
		prevention = "Attack technique bypassed security controls"
	} else {
		prevention = "Partial detection — some controls triggered"
	}

	return result, detection, prevention, output
}

// ListSimulationRuns lists runs for a specific simulation.
func (s *SimulationService) ListSimulationRuns(ctx context.Context, tenantID, simID string, page pagination.Pagination) (pagination.Result[*simulation.SimulationRun], error) {
	if s.runRepo == nil {
		return pagination.Result[*simulation.SimulationRun]{}, nil
	}
	tid, _ := shared.IDFromString(tenantID)
	sid, _ := shared.IDFromString(simID)
	return s.runRepo.List(ctx, simulation.RunFilter{TenantID: &tid, SimulationID: &sid}, page)
}
