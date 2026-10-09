package automation

// Loop guard (research/61 §1.5, decision A7). Automations can cause the events
// that start automations: "status -> in_progress => set confirmed" and
// "status -> confirmed => set in_progress" ping-pong forever, and
// "scan finished => run the scan" scans real targets in a loop.
//
// An event caused by an automation step carries its cause: the run and
// automation that caused it and the chain depth (a run started by a person
// or the platform has depth 0; an event caused by a run at depth n has depth
// n+1). Such an event:
//
//   - never starts the automation that caused it;
//   - starts another automation only when that automation allows it
//     (trigger_config.allow_automation_triggers: true; off by default);
//   - starts nothing beyond MaxChainDepth;
//   - starts an automation at most once per subject per SubjectCooldown.
//
// The cause travels in the context of the step (synchronous producers, such
// as a status change) and in the run context of a scan an automation starts
// (the scan_completed event comes later).

import (
	"context"
	"time"

	automationdom "github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	// MaxChainDepth is the deepest automation-caused event that still starts
	// an automation.
	MaxChainDepth = 3

	// SubjectCooldown: an automation-caused or AI-triage event starts an
	// automation at most once per subject in this window.
	SubjectCooldown = 10 * time.Minute

	// automationCauseKey holds the cause in trigger data and run contexts.
	automationCauseKey = "automation_cause"

	// allowAutomationTriggersKey is the trigger option that lets events
	// caused by other automations start this one.
	allowAutomationTriggersKey = "allow_automation_triggers"
)

// AutomationCause is what an automation-caused event carries.
type AutomationCause struct {
	RunID      shared.ID
	WorkflowID shared.ID
	// NodeKey is the step (node) of the run that caused the event: a scan
	// run started by an automation names the node that started it.
	NodeKey    string
	ChainDepth int
}

type automationCauseCtxKey struct{}

// WithAutomationCause returns ctx carrying the cause of the events a step
// produces.
func WithAutomationCause(ctx context.Context, c AutomationCause) context.Context {
	return context.WithValue(ctx, automationCauseCtxKey{}, c)
}

// AutomationCauseFrom returns the cause carried by ctx, if any.
func AutomationCauseFrom(ctx context.Context) (AutomationCause, bool) {
	c, ok := ctx.Value(automationCauseCtxKey{}).(AutomationCause)
	return c, ok
}

// data is the cause as stored in trigger data or a run context.
func (c AutomationCause) data() map[string]any {
	return map[string]any{
		"run_id":      c.RunID.String(),
		"workflow_id": c.WorkflowID.String(),
		"node_key":    c.NodeKey,
		"chain_depth": c.ChainDepth,
	}
}

// automationCauseFromData reads a cause stored by data(), from trigger data
// or a run context (numbers come back from JSON as float64).
func automationCauseFromData(m map[string]any) (AutomationCause, bool) {
	raw, ok := m[automationCauseKey].(map[string]any)
	if !ok {
		return AutomationCause{}, false
	}
	var c AutomationCause
	if s, ok := raw["run_id"].(string); ok {
		c.RunID, _ = shared.IDFromString(s)
	}
	if s, ok := raw["workflow_id"].(string); ok {
		c.WorkflowID, _ = shared.IDFromString(s)
	}
	c.NodeKey, _ = raw["node_key"].(string)
	switch d := raw["chain_depth"].(type) {
	case int:
		c.ChainDepth = d
	case int64:
		c.ChainDepth = int(d)
	case float64:
		c.ChainDepth = int(d)
	}
	if c.WorkflowID.IsZero() {
		return AutomationCause{}, false
	}
	return c, true
}

// runChainDepth is the depth of a run: the depth of the event that started
// it (0 for an event no automation caused).
func runChainDepth(run *automationdom.Run) int {
	if c, ok := automationCauseFromData(run.TriggerData); ok {
		return c.ChainDepth
	}
	return 0
}

// stepCause is the cause of the events the step nodeKey of run produces.
func stepCause(run *automationdom.Run, nodeKey string) AutomationCause {
	return AutomationCause{RunID: run.ID, WorkflowID: run.WorkflowID, NodeKey: nodeKey, ChainDepth: runChainDepth(run) + 1}
}

// loopBlocked reports why an automation-caused event must not start wf ("" when
// it may). cfg is wf's trigger config.
func loopBlocked(wf *automationdom.Workflow, cause *AutomationCause, cfg map[string]any) string {
	if cause == nil {
		return ""
	}
	if cause.WorkflowID == wf.ID {
		return "the event was caused by this automation"
	}
	if cause.ChainDepth > MaxChainDepth {
		return "automation chain too deep"
	}
	if allow, _ := cfg[allowAutomationTriggersKey].(bool); !allow {
		return "caused by another automation, and this one does not allow that"
	}
	return ""
}

// withCause adds the cause to trigger data (a copy) so the run knows its depth.
func withCause(data map[string]any, cause *AutomationCause) map[string]any {
	if cause == nil {
		return data
	}
	out := make(map[string]any, len(data)+1)
	for k, v := range data {
		out[k] = v
	}
	out[automationCauseKey] = cause.data()
	return out
}
