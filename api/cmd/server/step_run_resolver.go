package main

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// stepRunResolver finds the scan run of a step run for the new-asset
// notification's link. A step run or run of another tenant resolves to nothing.
type stepRunResolver struct {
	steps interface {
		GetByID(ctx context.Context, id shared.ID) (*scanrun.StepRun, error)
	}
	runs interface {
		GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*scanrun.Run, error)
	}
}

func (r stepRunResolver) RunOfStepRun(ctx context.Context, tenantID, stepRunID shared.ID) (shared.ID, bool) {
	step, err := r.steps.GetByID(ctx, stepRunID)
	if err != nil || step == nil {
		return shared.ID{}, false
	}
	run, err := r.runs.GetByTenantAndID(ctx, tenantID, step.ScanRunID)
	if err != nil || run == nil {
		return shared.ID{}, false
	}
	return run.ID, true
}
