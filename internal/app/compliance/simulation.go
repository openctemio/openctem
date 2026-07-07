package compliance

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/simulation"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// SafeCheckDispatcher dispatches a real, non-intrusive safe-check probe for a
// simulation run against a target asset (RFC-012 Phase 1b). Implemented by
// *validation.RunService. When wired, a network-addressable, safe-checkable
// simulation runs for real on an agent; the completion hook finalizes the run.
type SafeCheckDispatcher interface {
	DispatchSimulationCheck(ctx context.Context, tenantID, simRunID, assetID shared.ID, technique string) (shared.ID, error)
}

// SimulationService manages attack simulations and control tests.
type SimulationService struct {
	simRepo     simulation.SimulationRepository
	runRepo     simulation.RunRepository
	controlRepo simulation.ControlTestRepository
	safeCheck   SafeCheckDispatcher // optional (RFC-012 Phase 1b): real dispatch
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

// SetSafeCheckDispatcher wires the real safe-check dispatcher. When set, an
// eligible simulation (network-addressable target + safe-checkable technique)
// runs for real and returns a "running" run finalized asynchronously; otherwise
// it falls back to the clearly-labeled synthetic path.
func (s *SimulationService) SetSafeCheckDispatcher(d SafeCheckDispatcher) {
	s.safeCheck = d
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

	// RFC-012 Phase 1b: attempt a REAL safe-check dispatch first. Eligible when
	// a dispatcher is wired and the simulation has a network-addressable target
	// with a safe-checkable technique. On success the run stays "running" and is
	// finalized asynchronously by the command-completion hook; otherwise fall
	// through to the clearly-labeled synthetic path below.
	if s.tryDispatchLive(ctx, tid, sim, run) {
		return run, nil
	}

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
	detectionRate, preventionRate := resultRates(result)
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

// resultRates maps a run result to (detectionRate, preventionRate) for the
// simulation's rolling stats. Shared by the synthetic and live paths.
func resultRates(result simulation.RunResult) (detection, prevention float64) {
	switch result {
	case simulation.RunResultDetected:
		return 1.0, 0.0
	case simulation.RunResultPrevented:
		return 0.0, 1.0
	case simulation.RunResultPartial:
		return 0.5, 0.0
	default:
		return 0.0, 0.0
	}
}

// tryDispatchLive attempts a real safe-check dispatch for the run. Returns true
// when a job was enqueued (run left "running", persisted, to be finalized by the
// completion hook) and false when the caller should fall back to the synthetic
// path. Never returns an error: any ineligibility (no dispatcher, no target,
// non-network asset, unsupported technique, persist failure) is a soft fallback.
func (s *SimulationService) tryDispatchLive(ctx context.Context, tenantID shared.ID, sim *simulation.Simulation, run *simulation.SimulationRun) bool {
	if s.safeCheck == nil || s.runRepo == nil {
		return false
	}
	targets := sim.TargetAssets()
	if len(targets) == 0 {
		return false
	}
	assetID, err := shared.IDFromString(targets[0])
	if err != nil {
		return false
	}

	cmdID, err := s.safeCheck.DispatchSimulationCheck(ctx, tenantID, run.ID(), assetID, sim.MitreTechniqueID())
	if err != nil {
		s.logger.Debug("simulation live dispatch not applicable; using synthetic path",
			"simulation_id", sim.ID().String(), "reason", err.Error())
		return false
	}

	run.SetOutput(map[string]any{
		"execution_mode": "live",
		"verified":       true,
		"command_id":     cmdID.String(),
		"technique_id":   sim.MitreTechniqueID(),
		"target_asset":   assetID.String(),
		"status":         "dispatched — awaiting agent safe-check result",
	})
	if err := s.runRepo.Create(ctx, run); err != nil {
		s.logger.Warn("failed to persist running simulation run; falling back to synthetic",
			"simulation_id", sim.ID().String(), "error", err)
		return false
	}
	s.logger.Info("simulation dispatched for live safe-check",
		"simulation_id", sim.ID().String(), "run_id", run.ID().String(), "command_id", cmdID.String())
	return true
}

// FinalizeRun completes a running simulation run from a real agent safe-check
// outcome (RFC-012 Phase 1b — called by the command-completion hook). It maps
// the reachability outcome to a run result, updates the run + the simulation's
// rolling stats. Idempotent-friendly: a run that is no longer running is left
// untouched.
func (s *SimulationService) FinalizeRun(ctx context.Context, tenantID, runID shared.ID, outcome, summary string) error {
	if s.runRepo == nil {
		return fmt.Errorf("%w: simulation run repository not configured", shared.ErrValidation)
	}
	run, err := s.runRepo.GetByID(ctx, tenantID, runID)
	if err != nil {
		return err
	}
	if run.Status() != simulation.RunStatusRunning {
		// Already finalized (duplicate completion) — nothing to do.
		return nil
	}

	result, detection, prevention := mapOutcomeToResult(outcome)
	output := map[string]any{
		"execution_mode": "live",
		"verified":       true,
		"outcome":        outcome,
		"summary":        summary,
	}
	run.Complete(result, detection, prevention, output)
	if err := s.runRepo.Update(ctx, run); err != nil {
		return fmt.Errorf("failed to finalize simulation run: %w", err)
	}

	// Roll the simulation's stats forward (best-effort).
	if sim, gerr := s.simRepo.GetByID(ctx, tenantID, run.SimulationID()); gerr == nil {
		det, prev := resultRates(result)
		sim.RecordRun(string(result), det, prev)
		if uerr := s.simRepo.Update(ctx, sim); uerr != nil {
			s.logger.Warn("failed to update simulation stats after live finalize", "error", uerr)
		}
	}
	s.logger.Info("simulation run finalized from live safe-check",
		"run_id", runID.String(), "outcome", outcome, "result", string(result))
	return nil
}

// mapOutcomeToResult translates a validation safe-check outcome (reachability
// semantics) into a simulation run result:
//   - not_detected → prevented (target unreachable; control/segmentation held)
//   - detected     → bypassed  (target reachable; technique path is open)
//   - inconclusive → partial
//   - error/other  → error
func mapOutcomeToResult(outcome string) (result simulation.RunResult, detection, prevention string) {
	switch outcome {
	case "not_detected":
		return simulation.RunResultPrevented,
			"Live safe-check: target not reachable",
			"Reachability control held — technique path closed"
	case "detected":
		return simulation.RunResultBypassed,
			"Live safe-check: target reachable",
			"Target reachable — technique path is open"
	case "inconclusive":
		return simulation.RunResultPartial,
			"Live safe-check: inconclusive",
			"Partial signal"
	default:
		return simulation.RunResultError,
			"Live safe-check: error",
			"Probe did not complete"
	}
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

	// HONESTY (RFC-012 Phase 0): no live technique is executed here — the
	// outcome below is derived from configuration, not from exercising a
	// control. Flag every run as an unverified *simulation* so operators are
	// never told a control was validated when nothing ran. Phase 1 replaces
	// this with a real agent-dispatched safe-check (see RFC-012).
	output["verified"] = false
	output["execution_mode"] = "simulated"
	output["disclaimer"] = "No live technique execution — this is a configuration-based simulation of the expected posture, not a validated control test (RFC-012 Phase 0)."

	config := sim.Config()

	// Check if this is a dry run
	if dryRun, ok := config["dry_run"].(bool); ok && dryRun {
		output["dry_run"] = true
		return simulation.RunResultError, "dry_run: no execution performed", "n/a", output
	}

	// Derive the *simulated* expected posture from configuration. These values
	// describe intent, not a live result — hence verified:false above.
	detectionSource, _ := config["detection_source"].(string)

	switch sim.SimulationType() {
	case simulation.SimulationTypeAtomic:
		// Atomic: single technique test. A configured detection source means the
		// operator EXPECTS coverage — it is not proof the technique was caught.
		if detectionSource != "" {
			detection = fmt.Sprintf("Simulated: detection expected via %s (not live-validated)", detectionSource)
			result = simulation.RunResultDetected
			output["detection_source"] = detectionSource
			output["detection_validated"] = false
		} else {
			detection = "Simulated: no detection source configured"
			result = simulation.RunResultBypassed
			output["detection_validated"] = false
		}

	case simulation.SimulationTypeCampaign:
		// Campaign: multi-step attack chain (simulated, not executed).
		detection = "Simulated: campaign posture (steps not live-executed)"
		result = simulation.RunResultPartial
		output["campaign_steps"] = len(sim.TargetAssets())

	case simulation.SimulationTypeControlTest:
		// Control test: describes the expected control, not a live exercise.
		detection = "Simulated: control-test posture (not live-executed)"
		result = simulation.RunResultDetected
		output["control_test"] = true

	default:
		detection = "Unknown simulation type"
		result = simulation.RunResultError
	}

	// Prevention text mirrors the simulated posture — worded to avoid asserting
	// a real control outcome.
	switch result {
	case simulation.RunResultDetected:
		prevention = "Simulated: technique expected to be detected (not live-validated)"
	case simulation.RunResultBypassed:
		prevention = "Simulated: technique expected to bypass controls (not live-validated)"
	default:
		prevention = "Simulated: partial expected coverage (not live-validated)"
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
