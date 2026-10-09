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
// each step produced (counted in the caller's data scope), and how that
// compares with the previous run of the same scan.
type RunMap struct {
	Run      *scanrun.Run
	Workflow *scanworkflow.Workflow
	Shares   []command.StepSensorShare
	Plans    []scanrun.StagePlan
	Outputs  []scanrun.StepOutputCount
	// PreviousRunID is the previous finished run of the scan (zero: none);
	// Deltas compare each step's outputs with it.
	PreviousRunID shared.ID
	Deltas        []scanrun.StepOutputDelta
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
		if m.PreviousRunID, err = s.hops.PreviousRun(ctx, run.TenantID, run.ID); err != nil {
			return nil, fmt.Errorf("find the previous run: %w", err)
		}
		if m.Deltas, err = s.hops.CompareStepOutputs(ctx, run.TenantID, run.ID, m.PreviousRunID, scope); err != nil {
			return nil, fmt.Errorf("compare with the previous run: %w", err)
		}
	}
	return m, nil
}

// MaxStepOutputPreview is the most assets a step's output preview lists.
const MaxStepOutputPreview = 50

// StepOutputPreview is a sample of what one step of a run produced: up to
// the limit, new ones (not produced by the previous run's same step) first.
type StepOutputPreview struct {
	Outputs       []scanrun.StepOutput
	Total         int
	PreviousRunID shared.ID
}

// PreviewStepOutputs lists up to limit (1..MaxStepOutputPreview) assets one
// step of a run of the tenant produced, in the caller's data scope (nil:
// unrestricted). A run of another tenant is shared.ErrNotFound.
func (s *Service) PreviewStepOutputs(ctx context.Context, tenantID, runID, stepKey string, scope *shared.DataScope, limit int) (*StepOutputPreview, error) {
	run, err := s.GetRun(ctx, tenantID, runID)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > MaxStepOutputPreview {
		limit = MaxStepOutputPreview
	}
	p := &StepOutputPreview{Outputs: []scanrun.StepOutput{}}
	if s.hops == nil || stepKey == "" {
		return p, nil
	}
	if p.PreviousRunID, err = s.hops.PreviousRun(ctx, run.TenantID, run.ID); err != nil {
		return nil, fmt.Errorf("find the previous run: %w", err)
	}
	outs, total, err := s.hops.PreviewStepOutputs(ctx, run.TenantID, run.ID, p.PreviousRunID, stepKey, scope, limit)
	if err != nil {
		return nil, fmt.Errorf("preview the step's outputs: %w", err)
	}
	if outs != nil {
		p.Outputs = outs
	}
	p.Total = total
	return p, nil
}
