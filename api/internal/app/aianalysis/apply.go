package aianalysis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/activity"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	aidom "github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Timeline entry types of applied and undone suggestions.
const (
	ActivitySuggestionApplied vulnerability.ActivityType = "ai_suggestion_applied"
	ActivitySuggestionUndone  vulnerability.ActivityType = "ai_suggestion_undone"
)

// DecideInput is a person's decision on a suggestion.
type DecideInput struct {
	TenantID     shared.ID
	SuggestionID shared.ID
	ActorID      shared.ID
	// CanApprove: the person holds findings:approve.
	CanApprove bool
	// ClosureReason is required to apply a false-positive verdict: the
	// person states why the finding is not a risk.
	ClosureReason string
	// Can reports whether the person holds a permission (nil denies all):
	// applying, dismissing or undoing needs the permission of the change
	// itself (RequiredPermission).
	Can   func(permission string) bool
	Audit auditapp.AuditContext
}

// Permissions the apply engine checks (the finding routes' own gates).
const (
	permFindingsWrite    = "findings:write"
	permFindingsSeverity = "findings:severity"
)

// RequiredPermission is the permission a person needs to apply, dismiss or
// undo a suggestion: the one that gates the same change made by hand.
func RequiredPermission(sg *aidom.Suggestion) string {
	if sg.Kind == aidom.KindSeverity {
		return permFindingsSeverity
	}
	return permFindingsWrite
}

func (in DecideInput) allowed(sg *aidom.Suggestion) error {
	if in.Can == nil || !in.Can(RequiredPermission(sg)) {
		return fmt.Errorf("%w: you do not have the permission this change needs", shared.ErrForbidden)
	}
	return nil
}

// ApplyResult is the outcome of Apply.
type ApplyResult struct {
	Suggestion *aidom.Suggestion
	// PendingApproval: the change waits in an approval request.
	PendingApproval bool
}

// severityPrevious is the previous value stored for a severity suggestion.
type severityPrevious struct {
	Severity string `json:"severity"`
	Override bool   `json:"override"`
	Applied  string `json:"applied"`
}

// Apply makes the change a suggestion proposes, as the person, through the
// same path a change made by hand takes: a severity change uses the
// severity rules (a downgrade may need approval), a false-positive verdict
// opens a status request with the person as requester (who then cannot
// approve it alone unless the organization allows it), additive kinds become
// part of the finding's record.
func (s *Service) Apply(ctx context.Context, in DecideInput) (*ApplyResult, error) {
	sg, err := s.load(ctx, in.TenantID, in.SuggestionID)
	if err != nil {
		return nil, err
	}
	if err := in.allowed(sg); err != nil {
		return nil, err
	}
	if !sg.State.IsActionable() {
		return nil, aidom.ErrStateChanged
	}
	actor := in.ActorID
	from := []aidom.State{aidom.StateOpen, aidom.StateNeedsReview}
	switch {
	case sg.Kind == aidom.KindSeverity:
		return s.applySeverity(ctx, in, sg, from)
	case sg.Kind == aidom.KindVerdict && sg.Direction == aidom.DirectionLowersRisk:
		var p aidom.VerdictPayload
		if err := json.Unmarshal(sg.Payload, &p); err != nil {
			return nil, fmt.Errorf("decode verdict: %w", err)
		}
		if in.ClosureReason == "" {
			return nil, fmt.Errorf("%w: choose why the finding is not a risk", shared.ErrValidation)
		}
		approvalID, err := s.actions.RequestFalsePositiveAsPerson(ctx, in.TenantID, sg.SubjectID, actor,
			in.ClosureReason, aiJustification(sg, p.Reason), in.CanApprove)
		if err != nil {
			return nil, err
		}
		out, err := s.repo.Transition(ctx, in.TenantID, sg.ID, aidom.Transition{
			From: from, To: aidom.StatePendingApproval, Actor: &actor, At: s.now(),
			ApprovalKind: aidom.ApprovalKindStatus, ApprovalID: &approvalID,
		})
		if err != nil {
			return nil, err
		}
		s.auditEvent(ctx, in.Audit, audit.ActionAISuggestionApprovalRequested, sg.ID.String(), audit.SeverityMedium,
			map[string]any{"run_id": sg.RunID.String(), "approval_id": approvalID.String(), "finding_id": sg.SubjectID.String()})
		return &ApplyResult{Suggestion: out, PendingApproval: true}, nil
	default:
		out, err := s.repo.Transition(ctx, in.TenantID, sg.ID, aidom.Transition{
			From: from, To: aidom.StateApplied, Actor: &actor, At: s.now(), Applied: true,
		})
		if err != nil {
			return nil, err
		}
		s.recordActivity(ctx, out, ActivitySuggestionApplied, &actor, map[string]any{"run_id": sg.RunID.String()})
		s.auditEvent(ctx, in.Audit, audit.ActionAISuggestionApplied, sg.ID.String(), audit.SeverityLow,
			map[string]any{"run_id": sg.RunID.String(), "kind": string(sg.Kind), "finding_id": sg.SubjectID.String()})
		return &ApplyResult{Suggestion: out}, nil
	}
}

func (s *Service) applySeverity(ctx context.Context, in DecideInput, sg *aidom.Suggestion, from []aidom.State) (*ApplyResult, error) {
	var p aidom.SeverityPayload
	if err := json.Unmarshal(sg.Payload, &p); err != nil {
		return nil, fmt.Errorf("decode severity: %w", err)
	}
	f, err := s.findings.GetByID(ctx, in.TenantID, sg.SubjectID)
	if err != nil {
		return nil, err
	}
	prev, err := json.Marshal(severityPrevious{Severity: string(f.Severity()), Override: f.HasSeverityOverride(), Applied: p.Severity})
	if err != nil {
		return nil, fmt.Errorf("marshal previous value: %w", err)
	}
	actor := in.ActorID
	change, err := s.actions.ChangeSeverityAsPerson(ctx, in.TenantID, sg.SubjectID, actor, p.Severity, false,
		aiJustification(sg, p.Reason), in.CanApprove)
	if err != nil {
		return nil, err
	}
	t := aidom.Transition{From: from, Actor: &actor, At: s.now(), PreviousValue: prev}
	if change.Applied {
		t.To, t.Applied = aidom.StateApplied, true
	} else {
		t.To, t.ApprovalKind, t.ApprovalID = aidom.StatePendingApproval, aidom.ApprovalKindSeverity, change.RequestID
		if change.RequestID == nil {
			return nil, fmt.Errorf("%w: the severity change was neither applied nor requested", shared.ErrConflict)
		}
	}
	out, err := s.repo.Transition(ctx, in.TenantID, sg.ID, t)
	if err != nil {
		return nil, err
	}
	action := audit.ActionAISuggestionApplied
	if !change.Applied {
		action = audit.ActionAISuggestionApprovalRequested
	} else {
		s.recordActivity(ctx, out, ActivitySuggestionApplied, &actor, map[string]any{"run_id": sg.RunID.String(), "severity": p.Severity})
	}
	s.auditEvent(ctx, in.Audit, action, sg.ID.String(), audit.SeverityMedium,
		map[string]any{"run_id": sg.RunID.String(), "kind": string(sg.Kind), "finding_id": sg.SubjectID.String(),
			"severity_from": string(f.Severity()), "severity_to": p.Severity})
	return &ApplyResult{Suggestion: out, PendingApproval: !change.Applied}, nil
}

// aiJustification is the reason recorded on a change a person makes from a
// suggestion: it names the suggestion so the change can be traced.
func aiJustification(sg *aidom.Suggestion, reason string) string {
	j := "AI suggestion " + sg.ID.String()
	if reason != "" {
		j += ": " + reason
	}
	if r := []rune(j); len(r) > 1900 {
		j = string(r[:1900])
	}
	return j
}

// Dismiss records that a person declined a suggestion. It counts as an
// override for the use case's quality signal.
func (s *Service) Dismiss(ctx context.Context, in DecideInput) (*aidom.Suggestion, error) {
	sg, err := s.load(ctx, in.TenantID, in.SuggestionID)
	if err != nil {
		return nil, err
	}
	if err := in.allowed(sg); err != nil {
		return nil, err
	}
	actor := in.ActorID
	out, err := s.repo.Transition(ctx, in.TenantID, sg.ID, aidom.Transition{
		From: []aidom.State{aidom.StateOpen, aidom.StateNeedsReview}, To: aidom.StateDismissed, Actor: &actor, At: s.now(),
	})
	if err != nil {
		return nil, err
	}
	s.auditEvent(ctx, in.Audit, audit.ActionAISuggestionDismissed, sg.ID.String(), audit.SeverityLow,
		map[string]any{"run_id": sg.RunID.String(), "kind": string(sg.Kind), "finding_id": sg.SubjectID.String()})
	s.checkDowngrade(ctx, in.TenantID, sg.UseCase, in.Audit)
	return out, nil
}

// UndoResult is the outcome of Undo.
type UndoResult struct {
	Suggestion *aidom.Suggestion
	// PendingApproval: restoring the value needs approval (for example
	// lowering a severity back); the suggestion stays applied until then.
	PendingApproval bool
}

// Undo reverses an applied suggestion if the field has not changed since;
// otherwise it reports the conflict and changes nothing. It counts as an
// override.
func (s *Service) Undo(ctx context.Context, in DecideInput) (*UndoResult, error) {
	sg, err := s.load(ctx, in.TenantID, in.SuggestionID)
	if err != nil {
		return nil, err
	}
	if err := in.allowed(sg); err != nil {
		return nil, err
	}
	if !sg.State.IsApplied() {
		return nil, aidom.ErrStateChanged
	}
	actor := in.ActorID
	if sg.Kind == aidom.KindSeverity {
		var prev severityPrevious
		if err := json.Unmarshal(sg.PreviousValue, &prev); err != nil || prev.Severity == "" {
			return nil, &aidom.UndoConflictError{}
		}
		f, err := s.findings.GetByID(ctx, in.TenantID, sg.SubjectID)
		if err != nil {
			return nil, err
		}
		if string(f.Severity()) != prev.Applied {
			return nil, &aidom.UndoConflictError{Current: string(f.Severity())}
		}
		change, err := s.actions.ChangeSeverityAsPerson(ctx, in.TenantID, sg.SubjectID, actor, prev.Severity, !prev.Override,
			"Undo of AI suggestion "+sg.ID.String(), in.CanApprove)
		if err != nil {
			return nil, err
		}
		if !change.Applied {
			return &UndoResult{Suggestion: sg, PendingApproval: true}, nil
		}
	}
	out, err := s.repo.Transition(ctx, in.TenantID, sg.ID, aidom.Transition{
		From: []aidom.State{aidom.StateApplied, aidom.StateAutoApplied}, To: aidom.StateUndone, Actor: &actor,
		At: s.now(), Undone: true,
	})
	if err != nil {
		return nil, err
	}
	s.recordActivity(ctx, out, ActivitySuggestionUndone, &actor, map[string]any{"run_id": sg.RunID.String()})
	s.auditEvent(ctx, in.Audit, audit.ActionAISuggestionUndone, sg.ID.String(), audit.SeverityMedium,
		map[string]any{"run_id": sg.RunID.String(), "kind": string(sg.Kind), "finding_id": sg.SubjectID.String()})
	s.checkDowngrade(ctx, in.TenantID, sg.UseCase, in.Audit)
	return &UndoResult{Suggestion: out}, nil
}

// UndoRunResult reports a bulk undo.
type UndoRunResult struct {
	Undone    int
	Conflicts int
	Pending   int
}

// UndoRun undoes every applied suggestion of a run (incident response).
func (s *Service) UndoRun(ctx context.Context, in DecideInput, runID shared.ID) (*UndoRunResult, error) {
	detail, err := s.GetRun(ctx, in.TenantID, runID)
	if err != nil {
		return nil, err
	}
	res := &UndoRunResult{}
	for _, sg := range detail.Suggestions {
		if !sg.State.IsApplied() {
			continue
		}
		one := in
		one.SuggestionID = sg.ID
		r, err := s.Undo(ctx, one)
		switch {
		case err == nil && r.PendingApproval:
			res.Pending++
		case err == nil:
			res.Undone++
		case errors.Is(err, aidom.ErrUndoConflict), errors.Is(err, aidom.ErrStateChanged):
			res.Conflicts++
		default:
			return res, err
		}
	}
	return res, nil
}

// checkDowngrade moves an auto-apply use case back to suggest when people
// override too many of its suggestions (DowngradeThreshold over the last
// DowngradeWindow decisions). Only an administrator turns it back on.
func (s *Service) checkDowngrade(ctx context.Context, tenantID shared.ID, u aidom.UseCase, actx auditapp.AuditContext) {
	p, err := s.Policy(ctx, tenantID, u)
	if err != nil || p.Mode != aidom.ModeAutoApply {
		return
	}
	d, err := s.repo.RecentDecisions(ctx, tenantID, u, aidom.DowngradeWindow)
	if err != nil {
		s.logger.Warn("AI override rate unavailable", "use_case", string(u), "error", err)
		return
	}
	if !aidom.ShouldDowngrade(p.Mode, d) {
		return
	}
	changed, err := s.repo.Downgrade(ctx, tenantID, u, aidom.DowngradeReasonOverrideRate, s.now())
	if err != nil || !changed {
		return
	}
	actx.TenantID = tenantID.String()
	s.auditEvent(ctx, actx, audit.ActionAIUseCaseDowngraded, string(u), audit.SeverityHigh, map[string]any{
		"use_case": string(u), "decisions": d.Total, "overrides": d.Overrides,
		"threshold": aidom.DowngradeThreshold, "window": aidom.DowngradeWindow,
	})
	if s.notifier != nil {
		s.notifier.NotifyAIDowngrade(ctx, tenantID, u, d)
	}
}

// recordActivity writes a finding timeline entry for an applied or undone
// suggestion. A nil actor is the AI under the organization's auto-apply
// policy.
func (s *Service) recordActivity(ctx context.Context, sg *aidom.Suggestion, t vulnerability.ActivityType, actor *shared.ID, changes map[string]any) {
	if s.activity == nil || sg.SubjectType != aidom.SubjectFinding {
		return
	}
	changes["suggestion_id"] = sg.ID.String()
	changes["kind"] = string(sg.Kind)
	changes["direction"] = string(sg.Direction)
	in := activity.RecordActivityInput{
		TenantID:     sg.TenantID.String(),
		FindingID:    sg.SubjectID.String(),
		ActivityType: string(t),
		ActorType:    string(vulnerability.ActorTypeAI),
		Changes:      changes,
		Source:       string(vulnerability.SourceAuto),
	}
	if actor != nil {
		id := actor.String()
		in.ActorID = &id
		in.ActorType = string(vulnerability.ActorTypeUser)
		in.Source = string(vulnerability.SourceUI)
	}
	if _, err := s.activity.RecordActivity(ctx, in); err != nil {
		s.logger.Warn("failed to record AI suggestion activity", "suggestion_id", sg.ID.String(), "error", err)
	}
}

func (s *Service) auditEvent(ctx context.Context, actx auditapp.AuditContext, action audit.Action, resourceID string, sev audit.Severity, meta map[string]any) {
	if s.audit == nil {
		return
	}
	ev := auditEventFor(action, resourceID, sev, meta)
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.logger.Warn("failed to write AI audit event", "action", string(action), "error", err)
	}
}
