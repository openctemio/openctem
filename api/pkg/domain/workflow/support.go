package workflow

import (
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Some trigger and action types are valid enum values but do nothing:
//
//   - the schedule and finding_age triggers are stored but nothing ever fires
//     them (no scheduler or age sweep reads them);
//   - the assign_team and update_priority actions have no backing service and
//     fail every time they run;
//   - the run_script action is disabled (there is no sandbox to run a
//     tenant-supplied script in), so it fails every time it runs.
//
// They stay in the enum so stored workflows that use them still load, read
// and render. New writes are refused: creating a workflow, replacing its
// graph, adding or editing a node, or activating a workflow that uses one of
// them returns a 400 ErrValidation. Remove a type from these sets only when
// its runtime is built.

// ErrCodeUnsupportedWorkflowFeature is the domain error code for a workflow
// that uses a trigger or action type the platform does not execute.
const ErrCodeUnsupportedWorkflowFeature = "UNSUPPORTED_WORKFLOW_FEATURE"

// IsSupported reports whether the platform actually fires this trigger type.
func (t TriggerType) IsSupported() bool {
	switch t {
	case TriggerTypeSchedule, TriggerTypeFindingAge:
		return false
	}
	return true
}

// IsSupported reports whether the platform actually executes this action type.
func (t ActionType) IsSupported() bool {
	switch t {
	case ActionTypeAssignTeam, ActionTypeUpdatePriority, ActionTypeRunScript:
		return false
	}
	return true
}

// UnsupportedFeature names the trigger or action type in this config that the
// platform does not execute, as "trigger:<type>" or "action:<type>". It
// returns "" when the config uses only supported types.
func (c NodeConfig) UnsupportedFeature() string {
	if c.TriggerType != "" && !c.TriggerType.IsSupported() {
		return "trigger:" + string(c.TriggerType)
	}
	if c.ActionType != "" && !c.ActionType.IsSupported() {
		return "action:" + string(c.ActionType)
	}
	return ""
}

// ValidateSupported returns a validation error when any of the configs uses a
// trigger or action type the platform does not execute.
func ValidateSupported(configs ...NodeConfig) error {
	var found []string
	seen := make(map[string]bool)
	for _, c := range configs {
		if f := c.UnsupportedFeature(); f != "" && !seen[f] {
			seen[f] = true
			found = append(found, f)
		}
	}
	if len(found) == 0 {
		return nil
	}
	return shared.NewDomainError(
		ErrCodeUnsupportedWorkflowFeature,
		fmt.Sprintf("workflow uses %s, which is not supported yet; remove it or choose another type",
			strings.Join(found, ", ")),
		shared.ErrValidation,
	)
}

// UnsupportedFeatures lists the unsupported trigger and action types the
// workflow's loaded nodes use, without duplicates, in node order. It is empty
// when the graph is not loaded or uses only supported types.
func (w *Workflow) UnsupportedFeatures() []string {
	var out []string
	seen := make(map[string]bool)
	for _, n := range w.Nodes {
		if n == nil {
			continue
		}
		if f := n.Config.UnsupportedFeature(); f != "" && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

// ValidateSupported returns a validation error when the workflow's loaded
// nodes use a trigger or action type the platform does not execute.
func (w *Workflow) ValidateSupported() error {
	configs := make([]NodeConfig, 0, len(w.Nodes))
	for _, n := range w.Nodes {
		if n != nil {
			configs = append(configs, n.Config)
		}
	}
	return ValidateSupported(configs...)
}
