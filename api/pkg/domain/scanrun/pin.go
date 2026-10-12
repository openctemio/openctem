package scanrun

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
)

// PinWorkflow saves the spec of w (loaded with its steps) as a version of the
// tenant's workflow, unless the latest version is the same, and pins the run
// to it. Call it before the run is stored. A nil store leaves the run
// unpinned: it then reads the live workflow.
func PinWorkflow(ctx context.Context, store scanworkflow.VersionStore, run *Run, w *scanworkflow.Workflow) error {
	if store == nil || run == nil || w == nil {
		return nil
	}
	version, digest, err := store.PinVersion(ctx, run.TenantID, w.ID, scanworkflow.SpecOf(w))
	if err != nil {
		return fmt.Errorf("pin the scan workflow version: %w", err)
	}
	run.ScanWorkflowVersion = version
	run.SpecDigest = digest
	return nil
}

// PinnedWorkflow is the workflow a run executes: live with the run's pinned
// version applied, or live itself for an unpinned run.
func PinnedWorkflow(ctx context.Context, store scanworkflow.VersionStore, run *Run, live *scanworkflow.Workflow) (*scanworkflow.Workflow, error) {
	if store == nil || run == nil || live == nil || run.ScanWorkflowVersion <= 0 {
		return live, nil
	}
	spec, err := store.GetVersion(ctx, run.TenantID, run.ScanWorkflowID, run.ScanWorkflowVersion)
	if err != nil {
		return nil, fmt.Errorf("load the run's scan workflow version %d: %w", run.ScanWorkflowVersion, err)
	}
	return spec.Workflow(live), nil
}
