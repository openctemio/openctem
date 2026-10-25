package scanrun

// Step run policies at dispatch: the run's depth decides whether a step
// runs and with which standard params, and an optional step that waits for
// a tool is skipped with the reason. Design: docs/architecture/scan-stages.md
// §1.5 (depth, run policies, optional steps).

import (
	"errors"
	"fmt"
	"strings"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// CodeToolNotInstalled is the code of an optional step skipped because no
// tool that runs its capability is installed.
const CodeToolNotInstalled = "TOOL_NOT_INSTALLED"

// codeNoMatchingTool is scan.ResolveStepTool's refusal when no active tool
// runs the step's capability.
const codeNoMatchingTool = "NO_MATCHING_TOOL"

// RunDepth is the depth a run started with (scan.RunDepth).
func RunDepth(run *scanrun.Run) scanworkflow.Depth { return scanapp.RunDepth(run) }

// depthSkipReason is why the step does not run at the run's depth ("" when
// it runs).
func depthSkipReason(run *scanrun.Run, step *scanworkflow.Step) string {
	return scanapp.DepthSkipReason(run, step)
}

// stepAtDepth is the step as it runs at the run's depth: its config with the
// depth's standard params merged over it. The step itself is not changed.
func stepAtDepth(run *scanrun.Run, step *scanworkflow.Step) *scanworkflow.Step {
	cfg := step.RunPolicy.ConfigAt(step.Config, RunDepth(run))
	if len(step.RunPolicy.Overlay(RunDepth(run)).Params) == 0 {
		return step
	}
	cp := *step
	cp.Config = cfg
	return &cp
}

// stepTargetCap is the step's target cap at the run's depth (0: the stage's
// own cap). Lower-only: the hop router never raises a stage or run cap.
func stepTargetCap(run *scanrun.Run, step *scanworkflow.Step) int {
	if step == nil {
		return 0
	}
	return step.RunPolicy.Overlay(RunDepth(run)).MaxTargets
}

// checkStepDepth refuses a resolved tool that sends traffic to its targets
// in a passive-depth run (the scheduler skips such a step first; this is
// the last check before a command exists).
func checkStepDepth(run *scanrun.Run, resolved scanapp.StepTool) error {
	if RunDepth(run) != scanworkflow.DepthPassive {
		return nil
	}
	if resolved.HasStage && !resolved.Stage.Tier.Passive() {
		return fmt.Errorf("%w: tool %s sends traffic to its targets and the run is at Passive depth; not dispatched",
			shared.ErrValidation, resolved.Name)
	}
	if resolved.HasStage && stage.ToolNetwork(resolved.Name).TouchesTargets() {
		return fmt.Errorf("%w: tool %s sends traffic to its targets and the run is at Passive depth; not dispatched",
			shared.ErrValidation, resolved.Name)
	}
	return nil
}

// optionalSkipMessage is the message of an optional step that cannot run
// because no tool implements its capability; "" when err is something else
// (or the step is not optional), which then fails the step as before.
func optionalSkipMessage(step *scanworkflow.Step, err error) string {
	if step == nil || !step.RunPolicy.Optional || err == nil {
		return ""
	}
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != codeNoMatchingTool {
		return ""
	}
	return fmt.Sprintf("skipped: available when a tool that runs %s is installed", optionalCapabilityName(step))
}

// optionalCapabilityName names the step's capability for the message.
func optionalCapabilityName(step *scanworkflow.Step) string {
	if st, ok := stage.ForStep(step.Tool, step.Capabilities); ok {
		return string(st.Key)
	}
	if len(step.Capabilities) > 0 {
		return step.Capabilities[0]
	}
	return step.Tool
}

// hasDepthParams reports whether the policy sets standard params at any
// depth.
func hasDepthParams(p scanworkflow.RunPolicy) bool {
	for _, o := range p.Depths {
		if len(o.Params) > 0 {
			return true
		}
	}
	return false
}

// checkRunPolicyParams checks the step's depth params against its
// capability contract: standard params only (no tool extras, which an auto
// step could hand to any implementation), each with the contract's type and
// bounds, and the step's config at each depth valid as a whole.
func checkRunPolicyParams(step *scanworkflow.Step, st stage.Stage) error {
	for _, d := range scanworkflow.Depths() {
		o, ok := step.RunPolicy.Depths[d]
		if !ok || len(o.Params) == 0 {
			continue
		}
		if key, ok := stage.InvalidStandardParam(st, o.Params); !ok {
			return fmt.Errorf("%w: step '%s': run_policy.depths.%s.params: %q is not a valid standard param of %s",
				shared.ErrValidation, step.StepKey, d, key, st.Name)
		}
		if stage.ValidateParams(st, step.RunPolicy.ConfigAt(step.Config, d), step.Tool) != nil {
			return fmt.Errorf("%w: step '%s': its settings at %s depth are not valid for %s",
				shared.ErrValidation, step.StepKey, d, st.Name)
		}
	}
	return nil
}

// validatedCapabilities are the capabilities the security validator checks
// for a step: an optional step's planned capability (it waits for a tool)
// is left to the workflow graph check, which accepts it only there; every
// other capability is checked as before.
func validatedCapabilities(caps []string, policy *scanworkflow.RunPolicy) []string {
	if policy == nil || !policy.Optional {
		return caps
	}
	out := make([]string, 0, len(caps))
	for _, c := range caps {
		if stage.IsPlanned(stage.Key(strings.ToLower(strings.TrimSpace(c)))) {
			continue
		}
		out = append(out, c)
	}
	return out
}
