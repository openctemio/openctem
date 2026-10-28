// Package aianalysis governs AI results: it stores every result as a typed
// suggestion with its run's provenance, computes the direction from the
// finding's facts, applies the organization's mode per use case (risk-lowering
// changes always become approval requests), and lets a person apply, dismiss
// or undo. Design: docs/architecture/ai-analysis.md.
package aianalysis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/activity"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	aidom "github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ConsentReader answers whether the organization consented to AI.
type ConsentReader interface {
	AIConsented(ctx context.Context, tenantID shared.ID) (bool, error)
}

// FindingReader reads a finding of the tenant.
type FindingReader interface {
	GetByID(ctx context.Context, tenantID, id shared.ID) (*vulnerability.Finding, error)
}

// SeverityChange is the outcome of a person's severity change: applied now,
// or waiting in a request.
type SeverityChange struct {
	Applied   bool
	RequestID *shared.ID
}

// FindingActions are the existing finding paths the apply engine goes
// through, so every rule of a change made by hand applies to a change a
// person makes from a suggestion (implemented by the finding service).
type FindingActions interface {
	// ChangeSeverityAsPerson changes the effective severity as the person:
	// at once for an upgrade or a downgrade they may decide alone, else as a
	// pending request.
	ChangeSeverityAsPerson(ctx context.Context, tenantID, findingID, actorID shared.ID, severity string, restore bool, reason string, canApprove bool) (SeverityChange, error)
	// RequestFalsePositiveAsPerson asks for the false-positive status as the
	// person (the organization's approval levels apply).
	RequestFalsePositiveAsPerson(ctx context.Context, tenantID, findingID, actorID shared.ID, closureReason, justification string, canApprove bool) (shared.ID, error)
	// ProposeFalsePositiveAsAI opens a pending false-positive request whose
	// requester is the AI actor, not a person; nil when none was created
	// (critical or high finding, one already pending, or rejected before).
	ProposeFalsePositiveAsAI(ctx context.Context, tenantID, findingID shared.ID, likelihood float64, rationale string) (*shared.ID, error)
}

// DowngradeNotifier tells an organization's administrators that a use case
// fell back to suggest.
type DowngradeNotifier interface {
	NotifyAIDowngrade(ctx context.Context, tenantID shared.ID, useCase aidom.UseCase, d aidom.Decisions)
}

// Service is the AI governance service.
type Service struct {
	repo      aidom.Repository
	consent   ConsentReader
	findings  FindingReader
	actions   FindingActions
	dataScope *datascope.Enforcer
	audit     *auditapp.AuditService
	activity  *activity.FindingActivityService
	notifier  DowngradeNotifier
	logger    *logger.Logger
	now       func() time.Time
}

// New builds the service.
func New(repo aidom.Repository, consent ConsentReader, findings FindingReader, actions FindingActions, log *logger.Logger) *Service {
	return &Service{repo: repo, consent: consent, findings: findings, actions: actions,
		logger: log.With("service", "ai_analysis"), now: time.Now}
}

// SetDataScope wires the Layer 2 data scope (nil = unrestricted, internal callers).
func (s *Service) SetDataScope(e *datascope.Enforcer) { s.dataScope = e }

// SetAuditService wires audit logging.
func (s *Service) SetAuditService(a *auditapp.AuditService) { s.audit = a }

// SetActivityService wires the finding timeline.
func (s *Service) SetActivityService(a *activity.FindingActivityService) { s.activity = a }

// SetDowngradeNotifier wires the downgrade notice.
func (s *Service) SetDowngradeNotifier(n DowngradeNotifier) { s.notifier = n }

// ---------------------------------------------------------------------------
// Use-case policy
// ---------------------------------------------------------------------------

// PolicyView is one use case as the console shows it.
type PolicyView struct {
	aidom.UseCasePolicy
	// EffectiveMode is off while the organization has not consented.
	EffectiveMode aidom.Mode
	Consented     bool
}

// Policy returns the policy of one use case (stored, or the platform default).
func (s *Service) Policy(ctx context.Context, tenantID shared.ID, u aidom.UseCase) (PolicyView, error) {
	all, err := s.ListPolicies(ctx, tenantID)
	if err != nil {
		return PolicyView{}, err
	}
	for _, p := range all {
		if p.UseCase == u {
			return p, nil
		}
	}
	return PolicyView{}, fmt.Errorf("%w: unknown AI use case", shared.ErrValidation)
}

// ListPolicies returns every use case's policy.
func (s *Service) ListPolicies(ctx context.Context, tenantID shared.ID) ([]PolicyView, error) {
	consented, err := s.consent.AIConsented(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("read AI consent: %w", err)
	}
	stored, err := s.repo.ListPolicies(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	byCase := map[aidom.UseCase]aidom.UseCasePolicy{}
	for _, p := range stored {
		byCase[p.UseCase] = p
	}
	out := make([]PolicyView, 0, len(aidom.UseCases()))
	for _, u := range aidom.UseCases() {
		p, ok := byCase[u]
		if !ok {
			p = aidom.DefaultPolicy(tenantID, u, consented)
		}
		out = append(out, PolicyView{UseCasePolicy: p, EffectiveMode: p.Effective(consented), Consented: consented})
	}
	return out, nil
}

// UpdatePolicyInput is an administrator's change of one use case. Nil fields
// keep the current value.
type UpdatePolicyInput struct {
	TenantID         shared.ID
	ActorID          shared.ID
	UseCase          string
	Mode             *string
	DataClassCeiling *string
	MinConfidence    *float64
	Triggers         []string
	BudgetShare      *int
	Audit            auditapp.AuditContext
}

// ErrConsentRequired: a use case cannot be turned on before the organization
// consented to AI.
var ErrConsentRequired = fmt.Errorf("%w: turn AI on for the organization first", shared.ErrValidation)

// UpdatePolicy validates and stores a use case policy; the change is a
// critical audit row. The route requires a fresh sign-in when the body turns
// auto-apply on or raises the data class above internal.
func (s *Service) UpdatePolicy(ctx context.Context, in UpdatePolicyInput) (PolicyView, error) {
	u, err := aidom.ParseUseCase(in.UseCase)
	if err != nil {
		return PolicyView{}, err
	}
	cur, err := s.Policy(ctx, in.TenantID, u)
	if err != nil {
		return PolicyView{}, err
	}
	next := cur.UseCasePolicy
	if in.Mode != nil {
		if next.Mode, err = aidom.ParseMode(*in.Mode); err != nil {
			return PolicyView{}, err
		}
	}
	if in.DataClassCeiling != nil {
		if next.DataClassCeiling, err = aidom.ParseDataClass(*in.DataClassCeiling); err != nil {
			return PolicyView{}, err
		}
	}
	if in.MinConfidence != nil {
		next.MinConfidence = *in.MinConfidence
	}
	if in.Triggers != nil {
		next.Triggers = next.Triggers[:0:0]
		for _, t := range in.Triggers {
			next.Triggers = append(next.Triggers, aidom.Trigger(t))
		}
	}
	if in.BudgetShare != nil {
		next.BudgetShare = *in.BudgetShare
	}
	if err := next.Validate(); err != nil {
		return PolicyView{}, err
	}
	if next.Mode != aidom.ModeOff && !cur.Consented {
		return PolicyView{}, ErrConsentRequired
	}
	actor := in.ActorID
	next.UpdatedBy = &actor
	if err := s.repo.UpsertPolicy(ctx, next); err != nil {
		return PolicyView{}, err
	}
	s.auditEvent(ctx, in.Audit, audit.ActionAIUseCaseUpdated, string(u), audit.SeverityCritical, map[string]any{
		"use_case":           string(u),
		"mode_from":          string(cur.Mode),
		"mode_to":            string(next.Mode),
		"data_class_from":    string(cur.DataClassCeiling),
		"data_class_to":      string(next.DataClassCeiling),
		"min_confidence":     next.MinConfidence,
		"loosened":           next.LoosensFrom(cur.UseCasePolicy),
		"cleared_downgrade":  cur.DowngradedAt != nil && next.Mode == aidom.ModeAutoApply,
		"budget_share":       next.BudgetShare,
		"triggers_requested": in.Triggers,
	})
	return s.Policy(ctx, in.TenantID, u)
}

// ---------------------------------------------------------------------------
// Recording results
// ---------------------------------------------------------------------------

// Proposal is one raw suggestion from an executor, before validation.
type Proposal struct {
	Kind       string
	Payload    json.RawMessage
	Confidence *float64
	Evidence   []aidom.Evidence
	// ReviewReasons the executor already knows (unknown placeholder, coerced
	// output).
	ReviewReasons []string
}

// RecordInput is a finished run and its proposals.
type RecordInput struct {
	Run       *aidom.Run
	Proposals []Proposal
	// KnownRefs are the evidence references that exist for this run
	// ("bundle:<field>" for each field sent, "tool:<n>" for each tool
	// output).
	KnownRefs map[string]bool
	// RunReviewReasons apply to every proposal (prompt-injection markers in
	// the input).
	RunReviewReasons []string
	// SchemaVersion of the output the proposals were validated against.
	SchemaVersion string
}

// RecordResult reports what was stored.
type RecordResult struct {
	Suggestions []*aidom.Suggestion
	// Rejected counts proposals refused by validation (never stored).
	Rejected int
}

// Record validates a run's proposals, computes their direction from the
// finding's facts, stores them and applies the organization's mode. Only
// proposals about the run's own subject are possible: the subject comes from
// the run, never from the proposal.
func (s *Service) Record(ctx context.Context, in RecordInput) (*RecordResult, error) {
	run := in.Run
	if run == nil || run.SubjectType != aidom.SubjectFinding {
		return nil, fmt.Errorf("%w: unsupported AI run subject", shared.ErrValidation)
	}
	finding, err := s.findings.GetByID(ctx, run.TenantID, run.SubjectID)
	if err != nil {
		return nil, err
	}
	facts := FactsOf(finding)
	res := &RecordResult{}
	items := make([]*aidom.Suggestion, 0, len(in.Proposals))
	for _, p := range in.Proposals {
		kind, err := aidom.ParseKind(p.Kind)
		if err != nil {
			res.Rejected++
			continue
		}
		payload, err := aidom.NormalizePayload(kind, p.Payload)
		if err != nil {
			res.Rejected++
			continue
		}
		var conf *float64
		if p.Confidence != nil && *p.Confidence >= 0 && *p.Confidence <= 1 {
			c := *p.Confidence
			conf = &c
		}
		evidence, reasons := aidom.CheckEvidence(p.Evidence, in.KnownRefs)
		reasons = appendUnique(reasons, in.RunReviewReasons...)
		reasons = appendUnique(reasons, p.ReviewReasons...)
		state := aidom.StateOpen
		if len(reasons) > 0 {
			state = aidom.StateNeedsReview
		}
		items = append(items, &aidom.Suggestion{
			TenantID:      run.TenantID,
			RunID:         run.ID,
			UseCase:       run.UseCase,
			SubjectType:   run.SubjectType,
			SubjectID:     run.SubjectID,
			Kind:          kind,
			Payload:       payload,
			SchemaVersion: in.SchemaVersion,
			Direction:     aidom.ComputeDirection(kind, payload, facts),
			Confidence:    conf,
			Evidence:      evidence,
			State:         state,
			ReviewReasons: reasons,
		})
	}
	if err := s.repo.CreateSuggestions(ctx, run.TenantID, items); err != nil {
		return nil, err
	}
	res.Suggestions = items

	policy, err := s.Policy(ctx, run.TenantID, run.UseCase)
	if err != nil {
		return res, err
	}
	for i, sg := range items {
		switch aidom.DecideAuto(policy.EffectiveMode, policy.MinConfidence, sg) {
		case aidom.AutoApply:
			if out, err := s.autoApply(ctx, run, sg); err != nil {
				s.logger.Warn("AI auto-apply failed", "suggestion_id", sg.ID.String(), "error", err)
			} else {
				items[i] = out
			}
		case aidom.AutoRequestApproval:
			if out, err := s.autoRequestApproval(ctx, run, sg); err != nil {
				s.logger.Warn("AI approval request failed", "suggestion_id", sg.ID.String(), "error", err)
			} else if out != nil {
				items[i] = out
			}
		case aidom.AutoKeepOpen:
		}
	}
	return res, nil
}

func appendUnique(dst []string, add ...string) []string {
	for _, a := range add {
		found := false
		for _, d := range dst {
			if d == a {
				found = true
				break
			}
		}
		if !found && a != "" {
			dst = append(dst, a)
		}
	}
	return dst
}

// FactsOf reads the finding facts the direction is computed from.
func FactsOf(f *vulnerability.Finding) approvalpolicy.Facts {
	facts := approvalpolicy.Facts{
		Severity: string(f.Severity()),
		KEV:      f.IsInKEV(),
		EPSS:     f.EPSSScore(),
	}
	if pc := f.PriorityClass(); pc != nil {
		facts.PriorityClass = string(*pc)
	}
	return facts
}

// autoApply applies an additive suggestion as the system. Additive kinds
// change no finding field: applying makes the plan or summary part of the
// finding's record, shown with the AI badge.
func (s *Service) autoApply(ctx context.Context, run *aidom.Run, sg *aidom.Suggestion) (*aidom.Suggestion, error) {
	if sg.Direction != aidom.DirectionAdditive || sg.Kind == aidom.KindSeverity {
		return nil, fmt.Errorf("%w: only additive suggestions are applied automatically", shared.ErrValidation)
	}
	out, err := s.repo.Transition(ctx, sg.TenantID, sg.ID, aidom.Transition{
		From: []aidom.State{aidom.StateOpen}, To: aidom.StateAutoApplied, At: s.now(), Applied: true,
	})
	if err != nil {
		return nil, err
	}
	s.recordActivity(ctx, out, vulnerability.ActivityType("ai_suggestion_applied"), nil, map[string]any{
		"auto_applied": true, "run_id": run.ID.String(), "model": run.Model, "prompt_template": run.PromptTemplateID,
	})
	s.auditEvent(ctx, auditapp.AuditContext{TenantID: sg.TenantID.String()}, audit.ActionAISuggestionAutoApplied,
		sg.ID.String(), audit.SeverityMedium, map[string]any{"run_id": run.ID.String(), "kind": string(sg.Kind), "finding_id": sg.SubjectID.String()})
	return out, nil
}

// autoRequestApproval turns a risk-lowering verdict into a pending approval
// requested by the AI actor. The finding does not change.
func (s *Service) autoRequestApproval(ctx context.Context, run *aidom.Run, sg *aidom.Suggestion) (*aidom.Suggestion, error) {
	if sg.Kind != aidom.KindVerdict || sg.Confidence == nil {
		return nil, nil
	}
	var p aidom.VerdictPayload
	if err := json.Unmarshal(sg.Payload, &p); err != nil || p.Verdict != aidom.VerdictLikelyFalsePositive {
		return nil, nil //nolint:nilerr // not a false-positive verdict: nothing to request
	}
	approvalID, err := s.actions.ProposeFalsePositiveAsAI(ctx, sg.TenantID, sg.SubjectID, *sg.Confidence, p.Reason)
	if err != nil || approvalID == nil {
		return nil, err
	}
	out, err := s.repo.Transition(ctx, sg.TenantID, sg.ID, aidom.Transition{
		From: []aidom.State{aidom.StateOpen}, To: aidom.StatePendingApproval, At: s.now(),
		ApprovalKind: aidom.ApprovalKindStatus, ApprovalID: approvalID,
	})
	if err != nil {
		return nil, err
	}
	s.auditEvent(ctx, auditapp.AuditContext{TenantID: sg.TenantID.String()}, audit.ActionAISuggestionApprovalRequested,
		sg.ID.String(), audit.SeverityMedium, map[string]any{"run_id": run.ID.String(), "approval_id": approvalID.String(),
			"finding_id": sg.SubjectID.String(), "requested_by": "system:ai"})
	return out, nil
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

// assertSubject applies the caller's data scope and pentest membership to
// the suggestion's subject (out of scope answers not found).
func (s *Service) assertSubject(ctx context.Context, tenantID shared.ID, subjectType aidom.SubjectType, subjectID shared.ID) error {
	if subjectType != aidom.SubjectFinding {
		return aidom.ErrSuggestionNotFound
	}
	if err := s.dataScope.AssertFinding(ctx, tenantID, subjectID); err != nil {
		return err
	}
	return s.dataScope.AssertFindingCampaign(ctx, tenantID, subjectID)
}

// AssertFinding applies the caller's data scope and pentest membership to a
// finding (out of scope answers not found).
func (s *Service) AssertFinding(ctx context.Context, tenantID, findingID shared.ID) error {
	return s.assertSubject(ctx, tenantID, aidom.SubjectFinding, findingID)
}

// ListForFinding lists a finding's suggestions, newest first, with the runs
// they came from (provenance for the card).
func (s *Service) ListForFinding(ctx context.Context, tenantID, findingID shared.ID) ([]*aidom.Suggestion, map[shared.ID]*aidom.Run, error) {
	if err := s.assertSubject(ctx, tenantID, aidom.SubjectFinding, findingID); err != nil {
		return nil, nil, err
	}
	items, err := s.repo.ListSuggestionsBySubject(ctx, tenantID, aidom.SubjectFinding, findingID, 100)
	if err != nil {
		return nil, nil, err
	}
	runs := map[shared.ID]*aidom.Run{}
	for _, it := range items {
		if _, ok := runs[it.RunID]; ok {
			continue
		}
		run, err := s.repo.GetRun(ctx, tenantID, it.RunID)
		if err != nil {
			return nil, nil, err
		}
		runs[it.RunID] = run
	}
	return items, runs, nil
}

// RunDetail is a run with its suggestions (the "why" view).
type RunDetail struct {
	Run         *aidom.Run
	Suggestions []*aidom.Suggestion
}

// GetRun returns a run and its suggestions.
func (s *Service) GetRun(ctx context.Context, tenantID, runID shared.ID) (*RunDetail, error) {
	run, err := s.repo.GetRun(ctx, tenantID, runID)
	if err != nil {
		return nil, err
	}
	if err := s.assertSubject(ctx, tenantID, run.SubjectType, run.SubjectID); err != nil {
		if errors.Is(err, shared.ErrNotFound) || errors.Is(err, shared.ErrForbidden) {
			return nil, aidom.ErrRunNotFound
		}
		return nil, err
	}
	items, err := s.repo.ListSuggestionsByRun(ctx, tenantID, runID)
	if err != nil {
		return nil, err
	}
	return &RunDetail{Run: run, Suggestions: items}, nil
}

// load reads a suggestion and applies the caller's scope to its subject.
func (s *Service) load(ctx context.Context, tenantID, id shared.ID) (*aidom.Suggestion, error) {
	sg, err := s.repo.GetSuggestion(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if err := s.assertSubject(ctx, tenantID, sg.SubjectType, sg.SubjectID); err != nil {
		if errors.Is(err, shared.ErrNotFound) || errors.Is(err, shared.ErrForbidden) {
			return nil, aidom.ErrSuggestionNotFound
		}
		return nil, err
	}
	return sg, nil
}

// SettingsConsent reads consent from the organization's AI settings: AI is
// consented when the organization opted in and did not turn AI off.
type SettingsConsent struct{ Repo tenant.AISettingsRepository }

// AIConsented implements ConsentReader.
func (c SettingsConsent) AIConsented(ctx context.Context, tenantID shared.ID) (bool, error) {
	if c.Repo == nil {
		return false, nil
	}
	a, err := c.Repo.Get(ctx, tenantID, tenant.AISettings{})
	if err != nil {
		return false, err
	}
	return a.EffectiveMode() != tenant.AIModeDisabled, nil
}
