package scanrun

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RunMap is what the live run map draws: the run with its step runs, the
// workflow version the run executes (nil for a run without a workflow), how
// each step's chunks stand per sensor, how each stage was planned, and what
// each step produced (counted in the caller's data scope).
type RunMap struct {
	Run      *scanrun.Run
	Workflow *scanworkflow.Workflow
	Shares   []command.StepSensorShare
	Plans    []scanrun.StagePlan
	Outputs  []scanrun.StepOutputCount
}

// GetRunMap reads a run's map in the tenant. A run of another tenant is
// shared.ErrNotFound. scope (nil: unrestricted) limits the output counts to
// assets the caller may see.
func (s *Service) GetRunMap(ctx context.Context, tenantID, runID string, scope *shared.DataScope) (*RunMap, error) {
	run, err := s.GetRunWithStepsForTenant(ctx, tenantID, runID)
	if err != nil {
		return nil, err
	}
	m := &RunMap{Run: run, Shares: []command.StepSensorShare{}}
	if !run.ScanWorkflowID.IsZero() {
		wf, err := s.runWorkflow(ctx, run)
		switch {
		case errors.Is(err, shared.ErrNotFound):
			// The workflow was deleted: the map falls back to the step runs.
		case err != nil:
			return nil, fmt.Errorf("load the run's workflow: %w", err)
		default:
			m.Workflow = wf
		}
	}
	if reader, ok := s.commandRepo.(command.StepShareReader); ok {
		shares, err := reader.StepSensorShares(ctx, run.TenantID, run.ID)
		if err != nil {
			return nil, fmt.Errorf("read the run's chunks: %w", err)
		}
		if shares != nil {
			m.Shares = shares
		}
	}
	if s.hops != nil {
		if m.Plans, err = s.hops.ListStagePlans(ctx, run.TenantID, run.ID); err != nil {
			return nil, fmt.Errorf("read the run's stage plans: %w", err)
		}
		if m.Outputs, err = s.hops.CountStepOutputs(ctx, run.TenantID, run.ID, scope); err != nil {
			return nil, fmt.Errorf("count the run's outputs: %w", err)
		}
	}
	return m, nil
}
