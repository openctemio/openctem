package scan

// Scan depth: how much of a workflow a scan's runs execute (passive,
// standard or deep), chosen when the scan is saved and copied into each
// run's context. Each workflow step reacts through its run policy
// (scanworkflow.RunPolicy). Design: docs/architecture/scan-stages.md §1.5.

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// optionalWithoutTool reports whether err is the refusal of an optional step
// that no installed tool implements: the step is skipped at dispatch with
// the reason, so it never refuses a run.
func optionalWithoutTool(step *scanworkflow.Step, err error) bool {
	var de *shared.DomainError
	return step != nil && step.RunPolicy.Optional && errors.As(err, &de) && de.Code == codeNoMatchingTool
}

// CodeDepthRunsNothing refuses a workflow scan whose depth leaves no step
// of the workflow able to start.
const CodeDepthRunsNothing = "DEPTH_RUNS_NOTHING"

// RunDepth is the depth a run started with; standard for a run that has
// none (started before depths, or without a scan).
func RunDepth(run *scanrun.Run) scanworkflow.Depth {
	if run == nil {
		return scanworkflow.DefaultDepth
	}
	raw, _ := run.Context[scanrun.RunContextKeyDepth].(string)
	d, err := scanworkflow.ParseDepth(raw)
	if err != nil {
		return scanworkflow.DefaultDepth
	}
	return d
}

// DepthSkipReason is why a workflow step does not run at the run's depth:
// an active step at passive depth, or a step below its minimum depth. ""
// when it runs.
func DepthSkipReason(run *scanrun.Run, step *scanworkflow.Step) string {
	if step == nil {
		return ""
	}
	return step.RunPolicy.DepthSkipReason(RunDepth(run), StepIntensityTier(step))
}

// checkDepthRunsSomething refuses a workflow scan whose depth skips every
// step that has no dependency: none of its runs could start.
func (s *Service) checkDepthRunsSomething(ctx context.Context, sc *scan.Scan) error {
	if sc.ScanType != scan.ScanTypeWorkflow || sc.ScanWorkflowID == nil || s.stepRepo == nil {
		return nil
	}
	steps, err := s.stepRepo.GetByScanWorkflowID(ctx, *sc.ScanWorkflowID)
	if err != nil {
		return fmt.Errorf("failed to get scan workflow steps: %w", err)
	}
	d := sc.EffectiveDepth()
	roots := 0
	for _, st := range steps {
		if len(st.DependsOn) > 0 {
			continue
		}
		roots++
		if st.RunPolicy.DepthSkipReason(d, StepIntensityTier(st)) == "" {
			return nil
		}
	}
	if roots == 0 {
		return nil // the workflow check reports a workflow with no first step
	}
	return shared.NewDomainError(CodeDepthRunsNothing,
		fmt.Sprintf("At %s depth no first step of this workflow can run (each one sends traffic to the targets or starts at a deeper depth). Choose a deeper depth or another workflow.", d.Label()),
		shared.ErrValidation)
}

// stepNotRunBy reports whether the scan's depth skips the step: its tool
// is then never needed and never refuses a run at the trigger.
func stepNotRunBy(sc *scan.Scan, step *scanworkflow.Step) bool {
	if step == nil {
		return true
	}
	return step.RunPolicy.DepthSkipReason(sc.EffectiveDepth(), StepIntensityTier(step)) != ""
}
