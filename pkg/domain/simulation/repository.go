package simulation

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// SimulationFilter defines criteria for filtering simulations.
type SimulationFilter struct {
	TenantID       *shared.ID
	SimulationType *SimulationType
	Status         *SimulationStatus
	Search         *string
}

// SimulationRepository defines persistence for simulations.
type SimulationRepository interface {
	Create(ctx context.Context, sim *Simulation) error
	GetByID(ctx context.Context, tenantID, id shared.ID) (*Simulation, error)
	Update(ctx context.Context, sim *Simulation) error
	Delete(ctx context.Context, tenantID, id shared.ID) error
	List(ctx context.Context, filter SimulationFilter, page pagination.Pagination) (pagination.Result[*Simulation], error)
}

// RunFilter defines criteria for filtering simulation runs.
type RunFilter struct {
	TenantID     *shared.ID
	SimulationID *shared.ID
	Status       *RunStatus
}

// RunRepository defines persistence for simulation runs.
type RunRepository interface {
	Create(ctx context.Context, run *SimulationRun) error
	GetByID(ctx context.Context, tenantID, id shared.ID) (*SimulationRun, error)
	Update(ctx context.Context, run *SimulationRun) error
	List(ctx context.Context, filter RunFilter, page pagination.Pagination) (pagination.Result[*SimulationRun], error)
}

// ControlTestFilter defines criteria for filtering control tests.
type ControlTestFilter struct {
	TenantID  *shared.ID
	Framework *string
	Status    *string
	Search    *string
}

// ControlTestRepository defines persistence for control tests.
type ControlTestRepository interface {
	Create(ctx context.Context, ct *ControlTest) error
	GetByID(ctx context.Context, tenantID, id shared.ID) (*ControlTest, error)
	Update(ctx context.Context, ct *ControlTest) error
	Delete(ctx context.Context, tenantID, id shared.ID) error
	List(ctx context.Context, filter ControlTestFilter, page pagination.Pagination) (pagination.Result[*ControlTest], error)
	GetStatsByFramework(ctx context.Context, tenantID shared.ID) ([]FrameworkStats, error)
}

// FrameworkStats holds aggregated control test statistics per framework.
type FrameworkStats struct {
	Framework  string `json:"framework"`
	Total      int64  `json:"total"`
	Passed     int64  `json:"passed"`
	Failed     int64  `json:"failed"`
	Partial    int64  `json:"partial"`
	Untested   int64  `json:"untested"`
	NotApplicable int64 `json:"not_applicable"`
}
