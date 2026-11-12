package finding

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Ready to close and Recently auto-closed
// (docs/architecture/finding-verification-plan.md). Reads and decisions run
// in the caller's data scope: a proposal on an asset the caller cannot see
// is neither listed nor decidable (not_found). Every decision is audited.

// ErrClosureReviewUnavailable: the store is not wired.
var ErrClosureReviewUnavailable = fmt.Errorf("%w: closure review is not configured", shared.ErrValidation)

// ClosureDecisionKind is what a person does with proposals.
type ClosureDecisionKind string

const (
	ClosureDecisionConfirm ClosureDecisionKind = "confirm"
	ClosureDecisionDismiss ClosureDecisionKind = "dismiss"
)

// DecideClosureInput is one confirm or dismiss request.
type DecideClosureInput struct {
	TenantID    string
	ActorID     string
	ActorName   string
	ProposalIDs []string
	Decision    ClosureDecisionKind
	// Reason is required to dismiss (vulnerability.ClosureDismissReason).
	Reason string
	Note   string
}

func (s *VulnerabilityService) closureRepo() (vulnerability.ClosureProposalRepository, error) {
	r, ok := s.findingRepo.(vulnerability.ClosureProposalRepository)
	if !ok {
		return nil, ErrClosureReviewUnavailable
	}
	return r, nil
}

// closureScope resolves the tenant and the caller's data scope.
func (s *VulnerabilityService) closureScope(ctx context.Context, tenantID string) (shared.ID, *shared.DataScope, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil || tid.IsZero() {
		return shared.ID{}, nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	if s.dataScope == nil {
		return tid, nil, nil
	}
	scope, err := s.dataScope.Resolve(ctx, tid)
	if err != nil {
		return shared.ID{}, nil, fmt.Errorf("failed to resolve data scope: %w", err)
	}
	return tid, scope, nil
}

// ListClosureProposals lists the pending proposals the caller may decide.
func (s *VulnerabilityService) ListClosureProposals(ctx context.Context, tenantID string, page pagination.Pagination) (pagination.Result[*vulnerability.ClosureProposalItem], error) {
	repo, err := s.closureRepo()
	if err != nil {
		return pagination.Result[*vulnerability.ClosureProposalItem]{}, err
	}
	tid, scope, err := s.closureScope(ctx, tenantID)
	if err != nil {
		return pagination.Result[*vulnerability.ClosureProposalItem]{}, err
	}
	return repo.ListClosureProposals(ctx, tid, scope, page)
}

// CountClosureProposals counts them (the Ready to close badge).
func (s *VulnerabilityService) CountClosureProposals(ctx context.Context, tenantID string) (int, error) {
	repo, err := s.closureRepo()
	if err != nil {
		return 0, err
	}
	tid, scope, err := s.closureScope(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	return repo.CountClosureProposals(ctx, tid, scope)
}

// ListRecentlyAutoClosed lists the findings the platform closed by itself in
// the last seven days.
func (s *VulnerabilityService) ListRecentlyAutoClosed(ctx context.Context, tenantID string, page pagination.Pagination) (pagination.Result[*vulnerability.AutoClosedItem], error) {
	repo, err := s.closureRepo()
	if err != nil {
		return pagination.Result[*vulnerability.AutoClosedItem]{}, err
	}
	tid, scope, err := s.closureScope(ctx, tenantID)
	if err != nil {
		return pagination.Result[*vulnerability.AutoClosedItem]{}, err
	}
	return repo.ListRecentlyAutoClosed(ctx, tid, scope, page)
}

func cleanClosureNote(note string) (string, error) {
	note = strings.TrimSpace(note)
	if utf8.RuneCountInString(note) > vulnerability.MaxClosureNoteLen {
		return "", fmt.Errorf("%w: note must be at most %d characters", shared.ErrValidation, vulnerability.MaxClosureNoteLen)
	}
	return note, nil
}

// parseProposalIDs validates and de-duplicates the ids (1 to the batch cap).
func parseProposalIDs(raw []string) ([]shared.ID, error) {
	if len(raw) == 0 || len(raw) > vulnerability.MaxClosureDecisionBatch {
		return nil, fmt.Errorf("%w: proposal_ids must hold 1 to %d ids", shared.ErrValidation, vulnerability.MaxClosureDecisionBatch)
	}
	seen := make(map[shared.ID]struct{}, len(raw))
	out := make([]shared.ID, 0, len(raw))
	for _, r := range raw {
		id, err := shared.IDFromString(r)
		if err != nil || id.IsZero() {
			return nil, fmt.Errorf("%w: invalid proposal id", shared.ErrValidation)
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}

// DecideClosureProposals confirms (the findings close as fixed, verified by
// the proposal's method) or dismisses (they stay open, with the reason)
// proposals. A proposal the caller cannot see, or no longer pending, is
// skipped as not_found; a confirm whose finding was seen again or left the
// open statuses is skipped as not_eligible.
func (s *VulnerabilityService) DecideClosureProposals(ctx context.Context, in DecideClosureInput) (vulnerability.ClosureDecisionResult, error) {
	repo, err := s.closureRepo()
	if err != nil {
		return vulnerability.ClosureDecisionResult{}, err
	}
	ids, err := parseProposalIDs(in.ProposalIDs)
	if err != nil {
		return vulnerability.ClosureDecisionResult{}, err
	}
	note, err := cleanClosureNote(in.Note)
	if err != nil {
		return vulnerability.ClosureDecisionResult{}, err
	}
	actorID, err := shared.IDFromString(in.ActorID)
	if err != nil || actorID.IsZero() {
		return vulnerability.ClosureDecisionResult{}, fmt.Errorf("%w: a person decides proposals", shared.ErrForbidden)
	}
	tid, scope, err := s.closureScope(ctx, in.TenantID)
	if err != nil {
		return vulnerability.ClosureDecisionResult{}, err
	}
	var (
		res    vulnerability.ClosureDecisionResult
		action auditdom.Action
		msg    string
	)
	switch in.Decision {
	case ClosureDecisionConfirm:
		res, err = repo.ConfirmClosureProposals(ctx, tid, scope, ids, actorID, in.ActorName, note)
		action, msg = auditdom.ActionFindingClosureConfirmed, "Confirmed %d proposed closes"
	case ClosureDecisionDismiss:
		reason, perr := vulnerability.ParseClosureDismissReason(in.Reason, note)
		if perr != nil {
			return vulnerability.ClosureDecisionResult{}, perr
		}
		res, err = repo.DismissClosureProposals(ctx, tid, scope, ids, actorID, reason, note)
		action, msg = auditdom.ActionFindingClosureDismissed, "Kept open %d proposed closes"
	default:
		return vulnerability.ClosureDecisionResult{}, fmt.Errorf("%w: decision must be confirm or dismiss", shared.ErrValidation)
	}
	if err != nil {
		return vulnerability.ClosureDecisionResult{}, err
	}
	s.auditClosureDecision(ctx, tid, in, action, fmt.Sprintf(msg, len(res.Applied)), res)
	return res, nil
}

// auditClosureDecision writes one row per decision request, with the
// findings it moved (bounded) and the dismissal reason.
func (s *VulnerabilityService) auditClosureDecision(ctx context.Context, tid shared.ID, in DecideClosureInput, action auditdom.Action, msg string, res vulnerability.ClosureDecisionResult) {
	if s.auditService == nil || len(res.Applied) == 0 {
		return
	}
	// One request decides at most MaxClosureDecisionBatch (200) proposals, so every
	// id fits: the row names all findings and proposals it moved.
	listed := make([]string, 0, len(res.Findings))
	for _, id := range res.Findings {
		listed = append(listed, id.String())
	}
	proposals := make([]string, 0, len(res.Applied))
	for _, id := range res.Applied {
		proposals = append(proposals, id.String())
	}
	severity := auditdom.SeverityMedium
	if in.Decision == ClosureDecisionConfirm {
		severity = auditdom.SeverityHigh
	}
	event := audit.NewSuccessEvent(action, auditdom.ResourceTypeFinding, "").
		WithMessage(msg).
		WithMetadata("count", len(res.Applied)).
		WithMetadata("skipped", len(res.Skipped)).
		WithMetadata("finding_ids", listed).
		WithMetadata("proposal_ids", proposals).
		WithMetadata("methods", res.Methods).
		WithSeverity(severity)
	if in.Decision == ClosureDecisionDismiss {
		event = event.WithMetadata("reason", in.Reason)
	}
	actx := audit.AuditContext{TenantID: tid.String(), ActorID: in.ActorID}
	if err := s.auditService.LogEvent(ctx, actx, event); err != nil {
		s.logger.Warn("failed to audit closure decision", "error", err)
	}
}

// ReopenAutoClosedNotFixed reopens a finding the platform closed by itself
// in the last seven days, as the caller saying it is not fixed. Not found
// when there is no such finding in the caller's scope.
func (s *VulnerabilityService) ReopenAutoClosedNotFixed(ctx context.Context, tenantID, findingID, actorID, actorName, note string) error {
	repo, err := s.closureRepo()
	if err != nil {
		return err
	}
	fid, err := shared.IDFromString(findingID)
	if err != nil || fid.IsZero() {
		return shared.ErrNotFound
	}
	uid, err := shared.IDFromString(actorID)
	if err != nil || uid.IsZero() {
		return fmt.Errorf("%w: a person reopens findings", shared.ErrForbidden)
	}
	note, err = cleanClosureNote(note)
	if err != nil {
		return err
	}
	tid, scope, err := s.closureScope(ctx, tenantID)
	if err != nil {
		return err
	}
	ok, err := repo.ReopenAutoClosedNotFixed(ctx, tid, scope, fid, uid, actorName, note)
	if err != nil {
		return err
	}
	if !ok {
		return shared.ErrNotFound
	}
	if s.auditService != nil {
		event := audit.NewSuccessEvent(auditdom.ActionFindingAutoCloseReopened, auditdom.ResourceTypeFinding, fid.String()).
			WithMessage("Reopened a finding the platform closed: not fixed").
			WithSeverity(auditdom.SeverityMedium)
		if err := s.auditService.LogEvent(ctx, audit.AuditContext{TenantID: tid.String(), ActorID: actorID}, event); err != nil {
			s.logger.Warn("failed to audit auto-close reopen", "error", err)
		}
	}
	return nil
}
