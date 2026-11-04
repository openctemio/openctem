package scan

// Validation of a scan's step_params (research/426 P0.1): each entry names a
// step of the scan's workflow, or every step of a capability, and holds only
// that capability's standard params. Tool extras, executor keys, unknown
// params, wrong types or bounds and intrusive template tags are refused when
// the scan is saved; the dispatch applies the entries after the depth overlay
// (scanrun stepAtDepth).

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

func invalidStepParams(format string, args ...any) error {
	return shared.NewDomainError(scan.CodeInvalidStepParams,
		"step_params: "+fmt.Sprintf(format, args...), shared.ErrValidation)
}

// applyStepParams validates and sets the scan's step params. nil leaves them
// unchanged; an empty map clears them. Params on a scan that is not a
// workflow scan are refused.
func (s *Service) applyStepParams(ctx context.Context, sc *scan.Scan, in scan.StepParams) error {
	if in == nil {
		return nil
	}
	if len(in) == 0 {
		return sc.SetStepParams(nil)
	}
	if err := in.CheckShape(); err != nil {
		return err
	}
	if sc.ScanType != scan.ScanTypeWorkflow || sc.ScanWorkflowID == nil || s.stepRepo == nil {
		return invalidStepParams("only a workflow scan takes step params")
	}
	steps, err := s.stepRepo.GetByScanWorkflowID(ctx, *sc.ScanWorkflowID)
	if err != nil {
		return fmt.Errorf("failed to get scan workflow steps: %w", err)
	}
	byKey := make(map[string]*scanworkflow.Step, len(steps))
	for _, st := range steps {
		byKey[st.StepKey] = st
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		var st stage.Stage
		if capKey := scan.CapabilityKey(key); capKey != "" {
			found, ok := stage.Lookup(stage.Key(capKey))
			if !ok {
				return invalidStepParams("%q: unknown capability", key)
			}
			st = found
			if !workflowHasCapability(steps, st) {
				return invalidStepParams("%q: no step of the workflow runs %s", key, capKey)
			}
		} else {
			step, ok := byKey[key]
			if !ok {
				return invalidStepParams("%q is not a step of the workflow", key)
			}
			found, ok := stage.ForStep(step.Tool, step.Capabilities)
			if !ok {
				return invalidStepParams("%q: the step has no capability with standard params", key)
			}
			st = found
		}
		if err := checkStepParamValues(st, in[key]); err != nil {
			return invalidStepParams("%q: %s", key, strings.TrimPrefix(err.Error(), "invalid step settings: "))
		}
	}
	return sc.SetStepParams(in)
}

func workflowHasCapability(steps []*scanworkflow.Step, st stage.Stage) bool {
	for _, step := range steps {
		if got, ok := stage.ForStep(step.Tool, step.Capabilities); ok && got.Key == st.Key {
			return true
		}
	}
	return false
}

// checkStepParamValues checks standard params of one capability and, for the
// template capability, the sensor tier's tag exclusions.
func checkStepParamValues(st stage.Stage, params map[string]any) error {
	if err := stage.ValidateStandardParams(st, params); err != nil {
		return err
	}
	if st.Key == stage.VulnTemplates {
		// The same checks a workflow step's nuclei settings get: severity
		// names, tag shape, and tags the sensor tier refuses.
		if _, err := scanworkflow.NormalizeStepConfig("nuclei", params); err != nil {
			return err
		}
	}
	return nil
}

// setRunStepParams copies the scan's step params into a run's context (and
// removes a stale entry the trigger's context may carry), so a run keeps the
// overrides it started with.
func setRunStepParams(runContext map[string]any, sc *scan.Scan) {
	if len(sc.StepParams) == 0 {
		delete(runContext, scanrun.RunContextKeyStepParams)
		return
	}
	runContext[scanrun.RunContextKeyStepParams] = map[string]map[string]any(sc.StepParams)
}

// StepWithScanParams is the step with the run's scan overrides merged over
// its config (the last layer of step config, depth overlay, scan override).
// The step itself is not changed. Run it before the tool is resolved so the
// override also decides which tools are eligible.
func StepWithScanParams(run *scanrun.Run, step *scanworkflow.Step) *scanworkflow.Step {
	if run == nil || step == nil {
		return step
	}
	sp := scan.StepParamsFromAny(run.Context[scanrun.RunContextKeyStepParams])
	capability := ""
	if st, ok := stage.ForStep(step.Tool, step.Capabilities); ok {
		capability = string(st.Key)
	}
	over := sp.ParamsFor(step.StepKey, capability)
	if len(over) == 0 {
		return step
	}
	cp := *step
	cp.Config = make(map[string]any, len(step.Config)+len(over))
	for k, v := range step.Config {
		cp.Config[k] = v
	}
	for k, v := range over {
		cp.Config[k] = v
	}
	return &cp
}
