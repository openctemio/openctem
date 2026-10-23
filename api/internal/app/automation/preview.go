package automation

// Preview and validate a draft (RFC-125 §6).
//
// Preview runs a draft graph against the latest subjects the caller may read
// (at most 100), through the simulate evaluator, and stores nothing. Validate
// checks a draft statically. Both read only, and both are rate limited per
// user at the route.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	automationdom "github.com/openctemio/openctem/api/pkg/domain/automation"
	integrationdom "github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// MaxPreviewSubjects is the most subjects a preview runs against.
const MaxPreviewSubjects = 100

// SubjectSampler lists the latest subjects of a kind in a data scope.
type SubjectSampler interface {
	// LatestFindingIDs returns the ids of the tenant's latest findings in
	// scope (nil scope: every finding), newest first.
	LatestFindingIDs(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, limit int) ([]shared.ID, error)
	// LatestAssetIDs is LatestFindingIDs for assets.
	LatestAssetIDs(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, limit int) ([]shared.ID, error)
}

// IntegrationLookup reads one integration of a tenant.
type IntegrationLookup interface {
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*integrationdom.Integration, error)
}

// WithWorkflowPreview sets what preview and validate read: the subject
// sampler, the evaluator and the integration lookup.
func WithWorkflowPreview(sampler SubjectSampler, evaluator StepEvaluator, integrations IntegrationLookup) WorkflowServiceOption {
	return func(s *WorkflowService) {
		s.sampler = sampler
		s.evaluator = evaluator
		s.integrations = integrations
	}
}

// DraftInput names the draft to preview or validate: the given nodes and
// edges, or the saved draft when Nodes is empty.
type DraftInput struct {
	TenantID   shared.ID
	UserID     shared.ID
	WorkflowID shared.ID
	Nodes      []CreateNodeInput
	Edges      []CreateEdgeInput
}

// draftWorkflow returns the automation with the draft graph to check.
func (s *WorkflowService) draftWorkflow(ctx context.Context, in DraftInput) (*automationdom.Workflow, error) {
	w, err := s.GetWorkflow(ctx, in.TenantID, in.WorkflowID)
	if err != nil {
		return nil, err
	}
	if len(in.Nodes) == 0 {
		return w, nil
	}
	draft := *w
	draft.Nodes, draft.Edges = nil, nil
	for _, n := range in.Nodes {
		node, err := automationdom.NewNode(w.ID, n.NodeKey, n.NodeType, n.Name)
		if err != nil {
			return nil, fmt.Errorf("node %s: %w", n.NodeKey, err)
		}
		node.Config = n.Config
		draft.Nodes = append(draft.Nodes, node)
	}
	for _, e := range in.Edges {
		edge, err := automationdom.NewEdge(w.ID, e.SourceNodeKey, e.TargetNodeKey)
		if err != nil {
			return nil, err
		}
		edge.SetSourceHandle(e.SourceHandle)
		draft.Edges = append(draft.Edges, edge)
	}
	return &draft, nil
}

// PreviewDelivery is one message or ticket the draft would send.
type PreviewDelivery struct {
	NodeKey   string
	SubjectID string
	Channel   string
	Target    string
	Payload   map[string]any
}

// PreviewResult is what a draft would do on the latest subjects.
type PreviewResult struct {
	Subjects   int
	SampleIDs  []string
	Steps      []automationdom.StepAggregate
	Deliveries []PreviewDelivery
}

// Preview runs the draft against the latest limit subjects the caller may
// read and returns the trace. Nothing is stored or sent.
func (s *WorkflowService) Preview(ctx context.Context, in DraftInput, limit int) (*PreviewResult, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > MaxPreviewSubjects {
		return nil, shared.NewDomainError("PREVIEW_LIMIT", fmt.Sprintf("limit is at most %d", MaxPreviewSubjects), shared.ErrValidation)
	}
	if s.sampler == nil || s.evaluator == nil {
		return nil, fmt.Errorf("%w: preview is not configured", shared.ErrNotImplemented)
	}
	if in.UserID.IsZero() {
		// Samples follow a person's data scope.
		return nil, fmt.Errorf("%w: a preview runs in a person's data scope", shared.ErrForbidden)
	}
	w, err := s.draftWorkflow(ctx, in)
	if err != nil {
		return nil, err
	}
	if err := w.ValidateSupported(); err != nil {
		return nil, err
	}
	if err := w.ValidateGraph(); err != nil {
		return nil, err
	}
	scope, err := s.callerScope(ctx, in.TenantID, in.UserID)
	if err != nil {
		return nil, err
	}
	ctx = s.withFindingViewer(ctx)
	if err := s.assertDraftSubjectsVisible(ctx, in.TenantID, w, scope); err != nil {
		return nil, err
	}
	triggers := w.GetTriggerNodes()
	trigger := triggers[0]
	subjects, err := s.previewSubjects(ctx, in.TenantID, trigger.Config.TriggerType, scope, limit)
	if err != nil {
		return nil, err
	}
	res := &PreviewResult{SampleIDs: []string{}, Deliveries: []PreviewDelivery{}}
	agg := newTraceSum(w)
	for _, sub := range subjects {
		if sub.finding != nil && !(&WorkflowEventDispatcher{}).matchesTriggerFilters(w, FindingEvent{Finding: sub.finding, EventType: trigger.Config.TriggerType}) {
			continue
		}
		res.Subjects++
		res.SampleIDs = append(res.SampleIDs, sub.id)
		if err := s.previewOne(ctx, w, trigger, sub, agg, res); err != nil {
			return nil, err
		}
	}
	res.Steps = agg.list()
	return res, nil
}

// errPreviewSubjectHidden refuses a preview whose draft names a finding or
// asset the caller may not read, exactly like one that does not exist.
var errPreviewSubjectHidden = shared.NewDomainError("PREVIEW_SUBJECT_NOT_FOUND",
	"a step names a finding or asset that is not in your data scope", shared.ErrNotFound)

// assertDraftSubjectsVisible refuses a draft whose steps name a fixed
// finding or asset (action_config finding_id, asset_id) outside the caller's
// scope: the evaluator reads such a subject to say what the step would do,
// and the preview would hand its title, severity and status to the caller.
// A nil scope (an owner) reads everything.
func (s *WorkflowService) assertDraftSubjectsVisible(ctx context.Context, tenantID shared.ID, w *automationdom.Workflow, scope *shared.DataScope) error {
	if scope == nil {
		return nil
	}
	reader, _ := s.runRepo.(automationdom.RunScopeReader)
	for _, n := range w.Nodes {
		findings, assets := stepSubjects(n.Config.ActionConfig, nil)
		for _, id := range append(findings, assets...) {
			if reader == nil {
				return errPreviewSubjectHidden
			}
			ok, err := reader.SubjectVisible(ctx, tenantID, id, scope)
			if err != nil {
				return err
			}
			if !ok {
				return errPreviewSubjectHidden
			}
		}
	}
	return nil
}

type previewSubject struct {
	id      string
	trigger map[string]any
	finding *vulnerability.Finding
}

// previewSubjects are the latest subjects of the trigger's kind in scope.
func (s *WorkflowService) previewSubjects(ctx context.Context, tenantID shared.ID, t automationdom.TriggerType, scope *shared.DataScope, limit int) ([]previewSubject, error) {
	var out []previewSubject
	switch t {
	case automationdom.TriggerTypeAssetDiscovered:
		ids, err := s.sampler.LatestAssetIDs(ctx, tenantID, scope, limit)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			a := map[string]any{"id": id.String()}
			if s.assets != nil {
				if as, err := s.assets.GetByID(ctx, tenantID, id); err == nil {
					a["name"], a["type"] = as.Name(), string(as.Type())
				}
			}
			out = append(out, previewSubject{id: id.String(), trigger: map[string]any{"asset": a, "assets": []any{a}}})
		}
	case automationdom.TriggerTypeScanCompleted:
		// A finished scan has no finding or asset to sample.
	default:
		ids, err := s.sampler.LatestFindingIDs(ctx, tenantID, scope, limit)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			if s.findings == nil {
				break
			}
			f, err := s.findings.GetByID(ctx, tenantID, id)
			if err != nil {
				continue
			}
			out = append(out, previewSubject{id: id.String(), finding: f,
				trigger: map[string]any{"event_type": string(t), "finding": findingTriggerSummary(f)}})
		}
	}
	return out, nil
}

// previewOne walks the graph for one subject, in memory.
func (s *WorkflowService) previewOne(ctx context.Context, w *automationdom.Workflow, trigger *automationdom.Node, sub previewSubject, agg *traceSum, res *PreviewResult) error {
	reached := map[string]bool{trigger.NodeKey: true}
	condResult := map[string]bool{}
	agg.add(trigger.NodeKey, automationdom.StepTrace{In: 1, Out: 1})
	cond := &DefaultConditionEvaluator{}
	for _, node := range topoOrder(w) {
		if node.NodeType == automationdom.NodeTypeTrigger {
			continue
		}
		if !nodeReached(w, node.NodeKey, reached, condResult) {
			var t automationdom.StepTrace
			t.Skip(automationdom.SkipBranchNotTaken, 1)
			agg.add(node.NodeKey, t)
			continue
		}
		reached[node.NodeKey] = true
		switch node.NodeType {
		case automationdom.NodeTypeCondition:
			ok, err := cond.Evaluate(ctx, node.Config.ConditionExpr, map[string]any{"trigger": sub.trigger, "context": map[string]any{}, "upstream": map[string]any{}})
			if err != nil {
				return shared.NewDomainError("CONDITION_INVALID", fmt.Sprintf("condition %s: %v", node.NodeKey, err), shared.ErrValidation)
			}
			condResult[node.NodeKey] = ok
			t := automationdom.StepTrace{In: 1}
			if ok {
				t.Out = 1
			} else {
				t.Skip(automationdom.SkipConditionFalse, 1)
			}
			agg.add(node.NodeKey, t)
		default:
			eff, err := s.evaluator.Evaluate(ctx, &EvalInput{TenantID: w.TenantID, WorkflowID: w.ID, NodeKey: node.NodeKey,
				Config: node.Config, TriggerData: sub.trigger})
			if err != nil {
				return err
			}
			agg.add(node.NodeKey, eff.Trace)
			if eff.Delivery != nil && len(res.Deliveries) < 50 {
				res.Deliveries = append(res.Deliveries, PreviewDelivery{NodeKey: node.NodeKey, SubjectID: sub.id,
					Channel: eff.Delivery.Channel, Target: eff.Delivery.Target, Payload: automationdom.DeliveryPayload(eff.Delivery.Payload)})
			}
		}
	}
	return nil
}

// nodeReached reports whether every edge into key comes from a reached node
// on its taken branch (the executor's rule).
func nodeReached(w *automationdom.Workflow, key string, reached, condResult map[string]bool) bool {
	in := false
	for _, e := range w.Edges {
		if e.TargetNodeKey != key {
			continue
		}
		in = true
		if !reached[e.SourceNodeKey] {
			return false
		}
		if r, isCond := condResult[e.SourceNodeKey]; isCond {
			if (e.SourceHandle == "yes" && !r) || (e.SourceHandle == "no" && r) {
				return false
			}
		}
	}
	return in
}

// topoOrder is the nodes in an order where every edge goes forward (the
// graph was validated acyclic).
func topoOrder(w *automationdom.Workflow) []*automationdom.Node {
	indeg := map[string]int{}
	for _, n := range w.Nodes {
		indeg[n.NodeKey] += 0
	}
	for _, e := range w.Edges {
		indeg[e.TargetNodeKey]++
	}
	var out []*automationdom.Node
	done := map[string]bool{}
	for len(out) < len(w.Nodes) {
		progressed := false
		for _, n := range w.Nodes {
			if done[n.NodeKey] || indeg[n.NodeKey] > 0 {
				continue
			}
			done[n.NodeKey] = true
			out = append(out, n)
			progressed = true
			for _, e := range w.Edges {
				if e.SourceNodeKey == n.NodeKey {
					indeg[e.TargetNodeKey]--
				}
			}
		}
		if !progressed {
			break
		}
	}
	return out
}

// traceSum adds step traces up in node order.
type traceSum struct {
	order []string
	steps map[string]*automationdom.StepAggregate
}

func newTraceSum(w *automationdom.Workflow) *traceSum {
	t := &traceSum{steps: map[string]*automationdom.StepAggregate{}}
	for _, n := range topoOrder(w) {
		t.order = append(t.order, n.NodeKey)
		t.steps[n.NodeKey] = &automationdom.StepAggregate{NodeKey: n.NodeKey}
	}
	return t
}

func (t *traceSum) add(key string, tr automationdom.StepTrace) {
	a, ok := t.steps[key]
	if !ok {
		return
	}
	a.In += tr.In
	a.Out += tr.Out
	for r, n := range tr.Skipped {
		if a.Skipped == nil {
			a.Skipped = map[string]int{}
		}
		a.Skipped[r] += n
	}
}

func (t *traceSum) list() []automationdom.StepAggregate {
	out := make([]automationdom.StepAggregate, 0, len(t.order))
	for _, k := range t.order {
		out = append(out, *t.steps[k])
	}
	return out
}

// Problem is one finding of validate. Problems block publishing; warnings
// do not.
type Problem struct {
	Code    string
	NodeKey string
	Message string
}

// ValidationResult lists a draft's problems and warnings.
type ValidationResult struct {
	Problems []Problem
	Warnings []Problem
}

// Validate checks a draft statically: types, graph, conditions, required
// settings, integrations, and whether it was simulated since its last edit.
// The route adds the permissions the caller lacks (they would own it when
// publishing).
func (s *WorkflowService) Validate(ctx context.Context, in DraftInput) (*ValidationResult, error) {
	w, err := s.draftWorkflow(ctx, in)
	if err != nil {
		return nil, err
	}
	res := &ValidationResult{Problems: []Problem{}, Warnings: []Problem{}}
	for _, n := range w.Nodes {
		if f := n.Config.UnsupportedFeature(); f != "" {
			res.Problems = append(res.Problems, Problem{Code: "UNSUPPORTED_TYPE", NodeKey: n.NodeKey, Message: f + " is not a supported type"})
		}
		res.Problems = append(res.Problems, configProblems(n)...)
		if n.NodeType == automationdom.NodeTypeCondition && n.Config.ConditionExpr != "" {
			if _, err := (&DefaultConditionEvaluator{}).Evaluate(ctx, n.Config.ConditionExpr, map[string]any{}); err != nil {
				res.Problems = append(res.Problems, Problem{Code: "CONDITION_INVALID", NodeKey: n.NodeKey, Message: err.Error()})
			} else if !conditionPathKnown(n.Config.ConditionExpr) {
				res.Warnings = append(res.Warnings, Problem{Code: "CONDITION_UNKNOWN_FIELD", NodeKey: n.NodeKey,
					Message: "the condition reads a field outside trigger, context or upstream; it is always empty"})
			}
		}
		res.Problems = append(res.Problems, s.integrationProblems(ctx, w.TenantID, n)...)
	}
	if err := automationdom.ValidateTriggerConfig(automationdom.DefinitionOf(w).Configs()...); err != nil {
		res.Problems = append(res.Problems, Problem{Code: "TRIGGER_CONFIG_INVALID", Message: err.Error()})
	}
	if err := w.ValidateGraph(); err != nil {
		code := "GRAPH_INVALID"
		var de *shared.DomainError
		if errors.As(err, &de) && de.Code != "" && de.Code != "VALIDATION" {
			code = strings.TrimPrefix(de.Code, "WORKFLOW_")
		}
		res.Problems = append(res.Problems, Problem{Code: code, Message: err.Error()})
	}
	if len(in.Nodes) == 0 && s.notSimulatedSinceEdit(ctx, w) {
		res.Warnings = append(res.Warnings, Problem{Code: "NO_SIMULATION_SINCE_EDIT",
			Message: "the draft has not run in simulate since it was last changed"})
	}
	return res, nil
}

// configProblems are the settings a step cannot run without.
func configProblems(n *automationdom.Node) []Problem {
	missing := func(field string) Problem {
		return Problem{Code: "CONFIG_MISSING", NodeKey: n.NodeKey, Message: field + " is required"}
	}
	c := n.Config.ActionConfig
	str := func(k string) string { v, _ := c[k].(string); return v }
	var out []Problem
	switch n.Config.ActionType {
	case automationdom.ActionTypeAssignUser:
		if str("user_id") == "" {
			out = append(out, missing("user_id"))
		}
	case automationdom.ActionTypeUpdateStatus:
		if str("status") == "" {
			out = append(out, missing("status"))
		}
	case automationdom.ActionTypeAddTags, automationdom.ActionTypeRemoveTags:
		if len(configTags(c)) == 0 {
			out = append(out, missing("tags"))
		}
	case automationdom.ActionTypeTriggerScan:
		if str("scan_id") == "" {
			out = append(out, missing("scan_id"))
		}
	case automationdom.ActionTypeCreateTicket:
		if strings.EqualFold(str("provider"), "github") && (str("owner") == "" || str("repo") == "") {
			out = append(out, missing("owner and repo"))
		}
	}
	return out
}

// integrationProblems checks a notification's integration exists in the tenant.
func (s *WorkflowService) integrationProblems(ctx context.Context, tenantID shared.ID, n *automationdom.Node) []Problem {
	if n.Config.NotificationType == "" || n.Config.NotificationType == automationdom.NotificationTypeEmail {
		return nil
	}
	idStr, _ := n.Config.NotificationConfig["integration_id"].(string)
	if idStr == "" {
		return []Problem{{Code: "INTEGRATION_MISSING", NodeKey: n.NodeKey, Message: "choose the integration this notification is sent through"}}
	}
	id, err := shared.IDFromString(idStr)
	if err != nil {
		return []Problem{{Code: "INTEGRATION_MISSING", NodeKey: n.NodeKey, Message: "integration_id is not an id"}}
	}
	if s.integrations == nil {
		return nil
	}
	if _, err := s.integrations.GetByTenantAndID(ctx, tenantID, id); err != nil {
		return []Problem{{Code: "INTEGRATION_MISSING", NodeKey: n.NodeKey, Message: "the integration does not exist in this organization"}}
	}
	return nil
}

// conditionPathKnown reports whether the condition's field starts at a part
// of the step input (trigger, context, upstream) or is a literal.
func conditionPathKnown(expr string) bool {
	e := strings.TrimSpace(expr)
	for _, op := range []string{"==", "!=", ">=", "<=", ">", "<", " in ", " contains "} {
		if i := strings.Index(e, op); i >= 0 {
			e = strings.TrimSpace(e[:i])
			break
		}
	}
	for _, p := range []string{"trigger.", "context.", "upstream.", "true", "false"} {
		if strings.HasPrefix(strings.ToLower(e), p) {
			return true
		}
	}
	return false
}

// notSimulatedSinceEdit reports whether the automation has no simulate run
// created after its last change.
func (s *WorkflowService) notSimulatedSinceEdit(ctx context.Context, w *automationdom.Workflow) bool {
	mode := automationdom.ModeSimulate
	page, err := s.ListRuns(ctx, ListWorkflowRunsInput{TenantID: w.TenantID, WorkflowID: &w.ID, Mode: &mode, Page: 1, PerPage: 1})
	if err != nil || len(page.Data) == 0 {
		return err == nil
	}
	return page.Data[0].CreatedAt.Before(w.UpdatedAt.Add(-time.Second))
}
