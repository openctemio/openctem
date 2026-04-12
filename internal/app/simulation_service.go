package app

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
	controlRepo simulation.ControlTestRepository
	logger      *logger.Logger
}

// NewSimulationService creates a new simulation service.
func NewSimulationService(simRepo simulation.SimulationRepository, controlRepo simulation.ControlTestRepository, log *logger.Logger) *SimulationService {
	return &SimulationService{simRepo: simRepo, controlRepo: controlRepo, logger: log}
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
	TenantID    string
	ControlID   string
	Status      string
	Evidence    string
	Notes       string
	TestedByID  string
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
