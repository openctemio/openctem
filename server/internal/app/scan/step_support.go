package scan

// A scan runs as far as the organization's tools and sensors support
// (docs/architecture/scan-stages.md, "Steps nothing here runs"). Creating or
// saving a scan never refuses it for a missing tool or sensor. At trigger
// time each step of a workflow is checked: a step that no tool runs (no
// tool provides its capability, its pinned tool is not installed or is
// turned off) or that no eligible sensor may run is skipped with its reason
// and code, required or optional; the steps that need its results are
// skipped as DEPENDENCY_SKIPPED; the run goes on with every step that can
// run and ends partial. Only a trigger in which no step can run is refused,
// as a blocked run with NO_RUNNABLE_STEPS naming what is missing.
//
// Safety gates are not part of this: scope, intensity, approvals and the
// passive-only entitlement still refuse the trigger. A skipped step never
// dispatches anything, so skipping can only narrow what a run does.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	tooldom "github.com/openctemio/openctem/api/internal/app/tool"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// CodeNoRunnableSteps refuses a workflow trigger in which no step can run:
// every step lacks a tool or a sensor that runs it, or needs one that does.
const CodeNoRunnableSteps = "NO_RUNNABLE_STEPS"

// maxNamedMissing is how many missing steps the refusal names.
const maxNamedMissing = 5

// StepSkip is why a step does not run in a run: the step run's code
// (scanrun Failure* codes) and its reason in words.
type StepSkip struct {
	Code   string
	Reason string
	// Dependency: skipped because a step it needs was skipped.
	Dependency bool
}

// NoToolSkipReason is the reason of a step skipped because no tool runs its
// capability.
func NoToolSkipReason(step *scanworkflow.Step) string {
	return fmt.Sprintf("skipped: available when a tool that runs %s is installed", StepCapabilityName(step))
}

// StepCapabilityName names a step's capability for a reason: the catalog
// stage it runs, else its first capability, else its tool.
func StepCapabilityName(step *scanworkflow.Step) string {
	if step == nil {
		return ""
	}
	if st, ok := stage.ForStep(step.Tool, step.Capabilities); ok {
		return string(st.Key)
	}
	if len(step.Capabilities) > 0 {
		return step.Capabilities[0]
	}
	return step.Tool
}

// UnsupportedStepSkip turns the refusal of a step's tool check into the skip
// it stands for: no tool runs the capability (NO_MATCHING_TOOL), the pinned
// tool is not installed (TOOL_NOT_FOUND becomes TOOL_NOT_INSTALLED) or is
// turned off (TOOL_DISABLED). Any other error (a step that is not valid, a
// collector or connector as a step, a store error) is not a skip.
func UnsupportedStepSkip(step *scanworkflow.Step, err error) (StepSkip, bool) {
	var de *shared.DomainError
	if step == nil || !errors.As(err, &de) {
		return StepSkip{}, false
	}
	switch de.Code {
	case codeNoMatchingTool:
		return StepSkip{Code: scanrun.FailureNoMatchingTool, Reason: NoToolSkipReason(step)}, true
	case "TOOL_NOT_FOUND":
		return StepSkip{Code: scanrun.FailureToolNotInstalled, Reason: fmt.Sprintf("skipped: tool %s is not installed in this organization", step.Tool)}, true
	case "TOOL_DISABLED":
		return StepSkip{Code: scanrun.FailureToolDisabled, Reason: "skipped: " + lowerFirst(de.Message)}, true
	}
	return StepSkip{}, false
}

// SkipDependents adds to skips every step that needs the results of a
// skipped step, transitively, as DEPENDENCY_SKIPPED. considered reports the
// steps the run would start (nil: every step). A workflow that continues on
// a failed dependency runs such steps on the scan's targets, so nothing is
// added.
func SkipDependents(steps []*scanworkflow.Step, skips map[string]StepSkip, continueOnFailure bool, considered func(*scanworkflow.Step) bool) {
	if continueOnFailure || len(skips) == 0 {
		return
	}
	for changed := true; changed; {
		changed = false
		for _, step := range steps {
			if _, done := skips[step.StepKey]; done || (considered != nil && !considered(step)) {
				continue
			}
			for _, dep := range step.DependsOn {
				if _, skipped := skips[dep]; skipped {
					skips[step.StepKey] = StepSkip{
						Code:       scanrun.FailureDependencySkipped,
						Reason:     fmt.Sprintf("skipped: it needs the results of step %q, which was skipped", dep),
						Dependency: true,
					}
					changed = true
					break
				}
			}
		}
	}
}

// NoRunnableStepsError is the refusal of a workflow run in which no step
// can run, naming the steps that miss a tool or a sensor and why (at most
// maxNamedMissing of them).
func NoRunnableStepsError(workflowName string, steps []*scanworkflow.Step, skips map[string]StepSkip) error {
	var named []string
	more := 0
	for _, step := range steps {
		skip, ok := skips[step.StepKey]
		if !ok || skip.Dependency {
			continue
		}
		if len(named) == maxNamedMissing {
			more++
			continue
		}
		name := step.Name
		if name == "" {
			name = step.StepKey
		}
		named = append(named, fmt.Sprintf("%s (%s)", name, strings.TrimPrefix(skip.Reason, "skipped: ")))
	}
	if more > 0 {
		named = append(named, fmt.Sprintf("%d more", more))
	}
	return shared.NewDomainError(CodeNoRunnableSteps,
		fmt.Sprintf("No step of workflow %q can run here, so nothing was started. Missing: %s. Install or enable a tool, or add a sensor with it, then run the scan again.",
			workflowName, strings.Join(named, "; ")),
		shared.ErrValidation)
}

// workflowStepSkips checks every step a workflow scan's run would start
// (its depth decides which) against the organization's tools and sensors:
// the steps to skip with their reasons, or NO_RUNNABLE_STEPS when none can
// run. Every lookup is scoped to the scan's tenant (its own and platform
// tools, its own sensors and the platform scanning it is offered), so
// another organization's tool or sensor never counts. A step that is not
// valid (no tool or capability, a collector or connector as its tool) still
// refuses the trigger with its own code.
func (s *Service) workflowStepSkips(ctx context.Context, sc *scan.Scan, wf *scanworkflow.Workflow, steps []*scanworkflow.Step) (map[string]StepSkip, error) {
	ctx = tooldom.WithAvailabilityMemo(ctx) // one tenant view for every step tool
	considered := func(step *scanworkflow.Step) bool { return !stepNotRunBy(sc, step) }
	skips := map[string]StepSkip{}
	count := 0
	for _, step := range steps {
		if !considered(step) {
			continue
		}
		count++
		if err := s.validateStepTool(ctx, sc.TenantID, step); err != nil {
			skip, ok := UnsupportedStepSkip(step, err)
			if !ok {
				return nil, err
			}
			skips[step.StepKey] = skip
			continue
		}
		if s.toolAvailability == nil {
			continue
		}
		name := s.stepToolName(ctx, sc.TenantID, step)
		if name == "" {
			continue
		}
		if err := s.checkToolDispatchable(ctx, sc, name, ""); err != nil {
			var tu *ToolUnavailableError
			if !errors.As(err, &tu) {
				return nil, err
			}
			skips[step.StepKey] = StepSkip{Code: scanrun.FailureNoSensorForTool, Reason: "skipped: " + lowerFirst(tu.Domain.Message)}
		}
	}
	continueOnFailure := wf != nil && wf.Settings.ContinueOnFailedDependency
	SkipDependents(steps, skips, continueOnFailure, considered)
	runnable := 0
	for _, step := range steps {
		if _, skipped := skips[step.StepKey]; !skipped && considered(step) {
			runnable++
		}
	}
	if count > 0 && runnable == 0 {
		name := ""
		if wf != nil {
			name = wf.Name
		}
		return nil, NoRunnableStepsError(name, steps, skips)
	}
	return skips, nil
}
