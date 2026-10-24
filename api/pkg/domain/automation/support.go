package automation

import (
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Removed types. The schedule, finding_age, finding_updated and webhook
// triggers, the assign_team, update_priority, run_script, http_request and
// trigger_pipeline actions and the pagerduty notification never ran (nothing
// fired them, or every run failed or was refused). They are no longer types:
// writing a node that names one is refused, and migration
// automations_removed_types switched off every automation that still held
// one (disabled_reason = uses_removed_type) and dropped the stored headers of
// http_request nodes. Such an automation stays readable; the node is shown
// as a removed type until it is replaced, and the automation cannot be
// switched on before that.

// ErrCodeUnsupportedWorkflowFeature is the domain error code for a workflow
// that uses a trigger, action or notification type the platform does not have.
const ErrCodeUnsupportedWorkflowFeature = "UNSUPPORTED_WORKFLOW_FEATURE"

// DisabledReasonRemovedType is automations.disabled_reason for an automation
// switched off because it holds a removed trigger, action or notification type.
const DisabledReasonRemovedType = "uses_removed_type"

// DisabledReasonStatusNotAllowed is automations.disabled_reason for an
// automation switched off because it set a status automations may not set.
const DisabledReasonStatusNotAllowed = "status_not_allowed"

// UnsupportedFeature names the trigger, action or notification type in this
// config that the platform does not have, as "trigger:<type>",
// "action:<type>" or "notification:<type>". It returns "" when the config
// uses only known types.
func (c NodeConfig) UnsupportedFeature() string {
	if c.TriggerType != "" && !c.TriggerType.IsValid() {
		return "trigger:" + string(c.TriggerType)
	}
	if c.ActionType != "" && !c.ActionType.IsValid() {
		return "action:" + string(c.ActionType)
	}
	if c.NotificationType != "" && !c.NotificationType.IsValid() {
		return "notification:" + string(c.NotificationType)
	}
	return ""
}

// ValidateSupported returns a validation error when any of the configs uses a
// trigger, action or notification type the platform does not have.
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
	msg := fmt.Sprintf("workflow uses %s, which is not a supported type; remove it or choose another type",
		strings.Join(found, ", "))
	if seen["action:trigger_pipeline"] {
		msg += " (to run a scan workflow, save it as a scan and use trigger_scan)"
	}
	return shared.NewDomainError(ErrCodeUnsupportedWorkflowFeature, msg, shared.ErrValidation)
}

// UnsupportedFeatures lists the unknown trigger, action and notification
// types the workflow's loaded nodes use, without duplicates, in node order.
// It is empty when the graph is not loaded or uses only known types.
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
// nodes use a trigger, action or notification type the platform does not have.
func (w *Workflow) ValidateSupported() error {
	configs := make([]NodeConfig, 0, len(w.Nodes))
	for _, n := range w.Nodes {
		if n != nil {
			configs = append(configs, n.Config)
		}
	}
	return ValidateSupported(configs...)
}
