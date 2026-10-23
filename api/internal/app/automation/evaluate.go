package automation

// Simulate by construction (RFC-125 D5).
//
// An action or notification step is either executed (ActionHandler,
// NotificationHandler: they hold the services that change data, open
// tickets, start scans and send messages) or evaluated (StepEvaluator: it
// works out what the step would do). A simulate run only ever reaches the
// evaluators, and the evaluators are built from read-only dependencies: the
// type gives them no way to write or to reach the network. A test walks the
// evaluator's fields and fails if an outbound client ever appears there.

import (
	"context"
	"fmt"
	"slices"
	"strings"

	automationdom "github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// EvalInput is one step to evaluate.
type EvalInput struct {
	TenantID    shared.ID
	WorkflowID  shared.ID
	RunID       shared.ID
	NodeKey     string
	Config      automationdom.NodeConfig
	TriggerData map[string]any
}

// Effect is what a step would do.
type Effect struct {
	Trace  automationdom.StepTrace
	Output map[string]any
	// Delivery is set for a step that would leave the platform (channel,
	// target and payload; the executor fills the rest).
	Delivery *automationdom.Delivery
	// Changes is how many changes the step would make.
	Changes int
}

// StepEvaluator works out, reading only, what an action or notification step
// would do.
type StepEvaluator interface {
	Evaluate(ctx context.Context, in *EvalInput) (*Effect, error)
}

// SimulateEvaluator is the production StepEvaluator. Its only dependency is a
// read-only finding reader: it cannot change data or send anything.
type SimulateEvaluator struct {
	findings FindingReader
}

var _ StepEvaluator = (*SimulateEvaluator)(nil)

// NewSimulateEvaluator builds the evaluator. findings may be nil (finding
// steps then report no_subject).
func NewSimulateEvaluator(findings FindingReader) *SimulateEvaluator {
	return &SimulateEvaluator{findings: findings}
}

// WithExecutorEvaluator sets the evaluator simulate runs use.
func WithExecutorEvaluator(ev StepEvaluator) WorkflowExecutorOption {
	return func(e *WorkflowExecutor) { e.evaluator = ev }
}

// Evaluate works out what the step would do.
func (s *SimulateEvaluator) Evaluate(ctx context.Context, in *EvalInput) (*Effect, error) {
	c := in.Config
	if c.NotificationType != "" {
		return s.notification(in), nil
	}
	switch c.ActionType {
	case automationdom.ActionTypeTriggerScan:
		scanID, _ := c.ActionConfig["scan_id"].(string)
		return would(map[string]any{"would": string(c.ActionType), "scan_id": scanID}), nil
	case automationdom.ActionTypeAddTags, automationdom.ActionTypeRemoveTags, automationdom.ActionTypeAssignUser,
		automationdom.ActionTypeUpdateStatus, automationdom.ActionTypeCreateTicket, automationdom.ActionTypeUpdateTicket,
		automationdom.ActionTypeTriggerAITriage:
		return s.findingAction(ctx, in)
	}
	return nil, fmt.Errorf("action type %s cannot be simulated", c.ActionType)
}

// would is the effect of a step that would make one change.
func would(out map[string]any) *Effect {
	out["simulated"] = true
	return &Effect{Trace: automationdom.StepTrace{In: 1, Out: 1}, Output: out, Changes: 1}
}

// leftAlone is the effect of a step that would do nothing, and why.
func leftAlone(reason string, out map[string]any) *Effect {
	out["simulated"] = true
	out["skipped"] = reason
	e := &Effect{Trace: automationdom.StepTrace{In: 1}, Output: out}
	e.Trace.Skip(reason, 1)
	return e
}

func (s *SimulateEvaluator) findingAction(ctx context.Context, in *EvalInput) (*Effect, error) {
	c := in.Config
	base := map[string]any{"would": string(c.ActionType)}
	f, idStr := s.subjectFinding(ctx, in)
	if f == nil {
		return leftAlone(automationdom.SkipNoSubject, base), nil
	}
	base["finding_id"] = idStr
	switch c.ActionType {
	case automationdom.ActionTypeAddTags, automationdom.ActionTypeRemoveTags:
		var changed []string
		for _, t := range configTags(c.ActionConfig) {
			has := slices.Contains(f.Tags(), t)
			if (c.ActionType == automationdom.ActionTypeAddTags) != has {
				changed = append(changed, t)
			}
		}
		if len(changed) == 0 {
			return leftAlone(automationdom.SkipNoChange, base), nil
		}
		base["tags"] = changed
	case automationdom.ActionTypeAssignUser:
		user, _ := c.ActionConfig["user_id"].(string)
		if a := f.AssignedTo(); a != nil && a.String() == user {
			return leftAlone(automationdom.SkipNoChange, base), nil
		}
		base["user_id"] = user
	case automationdom.ActionTypeUpdateStatus:
		target, _ := c.ActionConfig["status"].(string)
		if vulnerability.FindingStatus(target) == f.Status() {
			return leftAlone(automationdom.SkipNoChange, base), nil
		}
		base["from"], base["to"] = string(f.Status()), target
	case automationdom.ActionTypeCreateTicket:
		eff := would(base)
		eff.Delivery = ticketDelivery(c.ActionConfig, f)
		return eff, nil
	case automationdom.ActionTypeUpdateTicket:
		eff := would(base)
		eff.Delivery = &automationdom.Delivery{Channel: "jira", Payload: map[string]any{
			"finding_id": idStr, "would": "sync_status", "provider": "jira",
		}}
		return eff, nil
	}
	return would(base), nil
}

// subjectFinding loads the finding the step acts on; nil when the step names
// none or it cannot be read (the step then has no subject).
func (s *SimulateEvaluator) subjectFinding(ctx context.Context, in *EvalInput) (*vulnerability.Finding, string) {
	if s.findings == nil {
		return nil, ""
	}
	idStr, err := findingIDFromInput(&ActionInput{ActionConfig: in.Config.ActionConfig, TriggerData: in.TriggerData})
	if err != nil {
		return nil, ""
	}
	id, err := shared.IDFromString(idStr)
	if err != nil {
		return nil, ""
	}
	f, err := s.findings.GetByID(ctx, in.TenantID, id)
	if err != nil {
		return nil, ""
	}
	return f, idStr
}

// configTags are the tags an add_tags or remove_tags step names.
func configTags(cfg map[string]any) []string {
	raw, _ := cfg["tags"].([]any)
	out := make([]string, 0, len(raw))
	for _, t := range raw {
		out = append(out, fmt.Sprintf("%v", t))
	}
	return out
}

// ticketDelivery is the delivery of a create_ticket step for finding f.
func ticketDelivery(cfg map[string]any, f *vulnerability.Finding) *automationdom.Delivery {
	provider, _ := cfg["provider"].(string)
	payload := map[string]any{"finding_id": f.ID().String(), "title": f.Title(), "severity": string(f.Severity())}
	if strings.EqualFold(provider, "github") {
		owner, _ := cfg["owner"].(string)
		repo, _ := cfg["repo"].(string)
		payload["provider"], payload["repository"] = "github", owner+"/"+repo
		return &automationdom.Delivery{Channel: "github", Target: owner + "/" + repo, Payload: payload}
	}
	project, _ := cfg["project_key"].(string)
	if project == "" {
		project, _ = cfg["project"].(string)
	}
	issueType, _ := cfg["issue_type"].(string)
	payload["provider"], payload["project_key"], payload["issue_type"] = "jira", project, issueType
	return &automationdom.Delivery{Channel: "jira", Target: project, Payload: payload}
}

// notificationDelivery is the delivery of a notification step: where it goes
// and the allow-listed fields of what it says.
func notificationDelivery(in *NotificationInput) *automationdom.Delivery {
	h := &DefaultNotificationHandler{}
	title := h.resolveString(in.NotificationConfig, "title", in)
	if title == "" {
		title = "Workflow Notification"
	}
	severity := h.resolveString(in.NotificationConfig, "severity", in)
	if severity == "" {
		severity = "info"
	}
	target, _ := in.NotificationConfig["integration_id"].(string)
	if target == "" {
		target = "notification_outbox"
	}
	payload := map[string]any{
		"title": title, "severity": severity,
		"body_chars": len(h.resolveString(in.NotificationConfig, "body", in)),
	}
	if id := subjectFromTrigger(in.TriggerData); id != "" {
		payload["subject_id"] = id
	}
	return &automationdom.Delivery{Channel: string(in.NotificationType), Target: target, Payload: payload}
}

func (s *SimulateEvaluator) notification(in *EvalInput) *Effect {
	ni := &NotificationInput{
		TenantID: in.TenantID, WorkflowID: in.WorkflowID, RunID: in.RunID, NodeKey: in.NodeKey,
		NotificationType: in.Config.NotificationType, NotificationConfig: in.Config.NotificationConfig,
		TriggerData: in.TriggerData,
	}
	eff := would(map[string]any{"would": "notify:" + string(in.Config.NotificationType)})
	eff.Delivery = notificationDelivery(ni)
	return eff
}

// subjectFromTrigger is the finding or asset id the trigger names ("" for none).
func subjectFromTrigger(trigger map[string]any) string {
	for _, k := range []string{"finding", "asset"} {
		if m, ok := trigger[k].(map[string]any); ok {
			if id, ok := m["id"].(string); ok && id != "" {
				return id
			}
		}
	}
	if id, ok := trigger["finding_id"].(string); ok {
		return id
	}
	return ""
}
