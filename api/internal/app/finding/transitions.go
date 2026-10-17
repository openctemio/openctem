package finding

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	lc "github.com/openctemio/openctem/api/pkg/domain/findinglifecycle"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Every status change a person or a delegated actor makes goes through the
// transition engine (vulnerability.EvaluateTransition). This file loads the
// facts the engine needs, maps its decision to the errors the paths answer
// with, and serves the allowed moves of a finding and the bulk dry run.

// TransitionPermissions are the finding permissions the caller holds.
type TransitionPermissions struct {
	Status   bool // findings:status
	Verify   bool // findings:verify
	FixApply bool // findings:fix_apply
	Triage   bool // findings:triage
	Write    bool // findings:write
}

// transitionActor is the engine actor of a request: a workflow when the
// context carries an explicit system move, a person when actorID is a user,
// otherwise an organization API key.
func transitionActor(ctx context.Context, actorID string, p TransitionPermissions) vulnerability.TransitionActor {
	a := vulnerability.TransitionActor{
		Kind:      vulnerability.TransitionActorAPIKey,
		CanStatus: p.Status, CanVerify: p.Verify, CanFixApply: p.FixApply, CanTriage: p.Triage, CanWrite: p.Write,
	}
	// A verified Jira/GitHub webhook is the ticket actor: the engine lets it
	// report work state only (never a close).
	if _, ok := vulnerability.TicketInboundFrom(ctx); ok {
		a.Kind = vulnerability.TransitionActorTicket
		return a
	}
	if isSystemMove(ctx) {
		a.Kind = vulnerability.TransitionActorWorkflow
		return a
	}
	if uid, err := shared.IDFromString(actorID); err == nil && !uid.IsZero() {
		a.Kind, a.UserID = vulnerability.TransitionActorPerson, uid
	}
	return a
}

// transitionFacts loads, for each finding, what a decision about moving it
// to target needs: whether the actor may claim its fix (only for a fix
// claim) and whether its verification checklist is complete (only for a
// resolve). target "" loads both (the allowed-moves list).
func (s *VulnerabilityService) transitionFacts(ctx context.Context, tenantID shared.ID, a vulnerability.TransitionActor,
	findings []*vulnerability.Finding, target vulnerability.FindingStatus,
) (map[shared.ID]vulnerability.TransitionFacts, error) {
	out := make(map[shared.ID]vulnerability.TransitionFacts, len(findings))
	// Without an ownership checker wired (some tests compose the service
	// without one) every finding counts as the person's, as before the
	// engine; the composition root always wires it.
	var claimable map[shared.ID]bool
	if (target == "" || target == vulnerability.FindingStatusFixApplied) && a.IsPerson() && s.fixAppliers != nil && len(findings) > 0 {
		claimable = s.fixAppliers(ctx, tenantID, a.UserID, findings)
	}
	for _, f := range findings {
		facts := transitionFactsOf(f)
		facts.CanClaimFix = s.fixAppliers == nil || claimable[f.ID()]
		if (target == "" || target == vulnerability.FindingStatusResolved) && s.db != nil {
			if err := loadResolveEvidence(ctx, s.db, tenantID, f.ID(), &facts); err != nil {
				return nil, err
			}
		}
		out[f.ID()] = facts
	}
	return out, nil
}

// transitionFactsOf is the facts of a finding itself; the caller adds what
// depends on the actor (CanClaimFix) and on other rows (ChecklistComplete).
func transitionFactsOf(f *vulnerability.Finding) vulnerability.TransitionFacts {
	return vulnerability.TransitionFacts{
		Status: f.Status(), Source: f.Source(), Severity: f.Severity(),
		PriorityClass: priorityClassString(f), IsKEV: f.IsInKEV(),
	}
}

// personActor is a signed-in person on an action route, holding the
// permission that route requires.
func personActor(uid shared.ID, p TransitionPermissions) vulnerability.TransitionActor {
	return vulnerability.TransitionActor{
		Kind: vulnerability.TransitionActorPerson, UserID: uid,
		CanStatus: p.Status, CanVerify: p.Verify, CanFixApply: p.FixApply, CanTriage: p.Triage, CanWrite: p.Write,
	}
}

func priorityClassString(f *vulnerability.Finding) string {
	if pc := f.PriorityClass(); pc != nil {
		return string(*pc)
	}
	return ""
}

// transitionError maps a decision to the error the status paths answer with,
// in the order a caller fixes them: use the approval or duplicate flow, get
// the missing permission, pick a legal move, add the note, then whose
// finding it is. nil when the move is allowed and every input it needs is
// there (note is the request's note).
func transitionError(d vulnerability.TransitionDecision, note string) error {
	switch d.Mode {
	case vulnerability.TransitionRequest:
		return &vulnerability.ApprovalRequiredError{Status: d.To}
	case vulnerability.TransitionPicker:
		return vulnerability.ErrDuplicateNeedsCanonical
	}
	has := func(code, perm string) bool {
		for _, b := range d.Blocked {
			if b.Code == code && (perm == "" || b.Params["permission"] == perm) {
				return true
			}
		}
		return false
	}
	switch {
	case has(vulnerability.BlockPentestModule, ""):
		return d.Err()
	case has(vulnerability.BlockMissingPermission, "findings:verify"):
		return ErrResolveRequiresVerify
	case has(vulnerability.BlockMissingPermission, "findings:fix_apply"):
		return ErrFixApplyRequiresPermission
	case has(vulnerability.BlockTicketCannotClose, ""), has(vulnerability.BlockNotALifecycleMove, ""):
		return d.Err()
	}
	for _, r := range d.Requires {
		if r == vulnerability.RequireNote && strings.TrimSpace(note) == "" {
			return ErrNoteRequired
		}
	}
	switch {
	case has(vulnerability.BlockNotAPerson, ""):
		return ErrFixApplyNotAPerson
	case has(vulnerability.BlockNotFixOwner, ""):
		return ErrFixApplyNotYours
	}
	return d.Err()
}

// ListFindingTransitions returns every move the lifecycle has from the
// finding's status with the caller's decision for each: allowed, how, which
// inputs it needs, or why not. The finding must be in the caller's tenant
// and data scope (404 otherwise, never 403).
func (s *VulnerabilityService) ListFindingTransitions(ctx context.Context, tenantID, findingID, actorID string,
	perms TransitionPermissions,
) ([]lc.Decision, vulnerability.FindingStatus, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, "", fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	fid, err := shared.IDFromString(findingID)
	if err != nil {
		return nil, "", fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	f, err := s.findingRepo.GetByID(ctx, tid, fid)
	if err != nil {
		return nil, "", err
	}
	if err := s.assertFindingScope(ctx, f); err != nil {
		return nil, "", err
	}
	a := transitionActor(ctx, actorID, perms)
	facts, err := s.transitionFacts(ctx, tid, a, []*vulnerability.Finding{f}, "")
	if err != nil {
		return nil, "", err
	}
	cands, err := s.lifecycleCandidates(ctx, tid)
	if err != nil {
		return nil, "", err
	}
	lf := lifecycleFacts(f, facts[f.ID()])
	scheme := lc.SelectScheme(cands, lf.ConditionFacts())
	return lc.AvailableMoves(scheme, lf, lifecycleActor(ctx, a)), f.Status(), nil
}

// MaxTransitionEvaluate caps the findings of one dry run (the bulk status cap).
const MaxTransitionEvaluate = 100

// EvaluatedTransition is the dry-run decision for one finding. NotFound is
// set (and Decision empty) for an id that is not a finding the caller can
// see: another tenant's, out of the caller's data scope, or absent.
type EvaluatedTransition struct {
	FindingID string       `json:"finding_id"`
	NotFound  bool         `json:"not_found,omitempty"`
	Decision  *lc.Decision `json:"decision,omitempty"`
}

// EvaluateFindingTransitions is the bulk dry run: for each finding, whether
// the caller may move it to target and why not. It changes nothing.
func (s *VulnerabilityService) EvaluateFindingTransitions(ctx context.Context, tenantID string, findingIDs []string,
	target, subStatusID, actorID string, perms TransitionPermissions,
) ([]EvaluatedTransition, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	to, err := vulnerability.ParseFindingStatus(target)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}
	subID, err := parseSubStatus(subStatusID)
	if err != nil {
		return nil, err
	}
	if len(findingIDs) == 0 || len(findingIDs) > MaxTransitionEvaluate {
		return nil, fmt.Errorf("%w: finding_ids must hold 1 to %d ids", shared.ErrValidation, MaxTransitionEvaluate)
	}
	ids := make([]shared.ID, 0, len(findingIDs))
	for _, raw := range findingIDs {
		id, err := shared.IDFromString(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid finding id %q", shared.ErrValidation, raw)
		}
		ids = append(ids, id)
	}
	findings, err := s.findingRepo.GetByIDs(ctx, tid, ids)
	if err != nil {
		return nil, fmt.Errorf("failed to read findings: %w", err)
	}
	visible, err := s.visibleFindings(ctx, tid, findings)
	if err != nil {
		return nil, err
	}
	a := transitionActor(ctx, actorID, perms)
	list := make([]*vulnerability.Finding, 0, len(visible))
	for _, f := range visible {
		list = append(list, f)
	}
	facts, err := s.transitionFacts(ctx, tid, a, list, to)
	if err != nil {
		return nil, err
	}
	cands, err := s.lifecycleCandidates(ctx, tid)
	if err != nil {
		return nil, err
	}
	la := lifecycleActor(ctx, a)
	out := make([]EvaluatedTransition, 0, len(ids))
	for _, id := range ids {
		f, ok := visible[id]
		if !ok {
			out = append(out, EvaluatedTransition{FindingID: id.String(), NotFound: true})
			continue
		}
		d, _ := lifecycleDecision(cands, f, facts[f.ID()], la, lc.Target{Status: to, SubStatus: subID})
		out = append(out, EvaluatedTransition{FindingID: id.String(), Decision: &d})
	}
	return out, nil
}

// visibleFindings keeps the findings in the caller's data scope, by id.
func (s *VulnerabilityService) visibleFindings(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding,
) (map[shared.ID]*vulnerability.Finding, error) {
	out := make(map[shared.ID]*vulnerability.Finding, len(findings))
	if s.dataScope == nil {
		for _, f := range findings {
			out[f.ID()] = f
		}
		return out, nil
	}
	assetIDs := make([]shared.ID, 0, len(findings))
	for _, f := range findings {
		assetIDs = append(assetIDs, f.AssetID())
	}
	inScope, err := s.dataScope.FilterForCaller(ctx, tenantID, assetIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve data scope: %w", err)
	}
	for _, f := range findings {
		if inScope(f.AssetID()) {
			out[f.ID()] = f
		}
	}
	return out, nil
}

// bulkRefusalReason is the reason a bulk row reports for a refused finding:
// the engine's sentence without the error kind prefix.
func bulkRefusalReason(err error) string {
	var ar *vulnerability.ApprovalRequiredError
	if errors.As(err, &ar) {
		return ar.UserMessage()
	}
	msg := err.Error()
	for _, kind := range []error{shared.ErrValidation, shared.ErrForbidden} {
		msg = strings.TrimPrefix(msg, kind.Error()+": ")
	}
	return msg
}

// loadResolveEvidence adds to facts the proof a resolve may rest on: the
// finding's verification checklist (complete, and by whom) and whether its
// latest completed retest confirmed the fix. Only evidence newer than the
// finding's last reopen and last sighting counts: a regression, or a scan
// that still sees the finding, makes earlier proof stale, so a critical
// finding that came back cannot be closed on the evidence of the previous
// fix. Tenant-scoped reads.
func loadResolveEvidence(ctx context.Context, db *sql.DB, tenantID, findingID shared.ID, facts *vulnerability.TransitionFacts) error {
	var since sql.NullTime
	err := db.QueryRowContext(ctx, `
		SELECT GREATEST(last_reopened_at, last_seen_at) FROM findings
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), findingID.String()).Scan(&since)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read finding evidence horizon: %w", err)
	}
	fresh := func(at *time.Time) bool {
		return at != nil && (!since.Valid || at.After(since.Time))
	}

	checklist, err := loadVerificationChecklist(ctx, db, tenantID, findingID)
	if err != nil {
		return err
	}
	if checklist != nil && checklist.FindingID() == findingID && checklist.IsComplete() && fresh(checklist.CompletedAt()) {
		facts.ChecklistComplete = true
		if by := checklist.CompletedBy(); by != nil {
			facts.ChecklistCompletedBy = *by
		}
	}
	var (
		outcome     sql.NullString
		completedAt sql.NullTime
	)
	err = db.QueryRowContext(ctx, `
		SELECT outcome, completed_at FROM finding_retests
		WHERE tenant_id = $1 AND finding_id = $2 AND status = 'completed'
		ORDER BY completed_at DESC NULLS LAST
		LIMIT 1`, tenantID.String(), findingID.String()).Scan(&outcome, &completedAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read latest retest: %w", err)
	}
	var retestAt *time.Time
	if completedAt.Valid {
		retestAt = &completedAt.Time
	}
	facts.RetestConfirmedFixed = outcome.String == "confirmed_fixed" && fresh(retestAt)
	return nil
}
