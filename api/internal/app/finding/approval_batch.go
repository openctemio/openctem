package finding

// Group-level exceptions (api/docs/rfcs/RFC-111-approval-policy.md §7): one
// request to accept the risk of, or mark false positive, the open findings of
// a remediation task, decided once.
//
// Threat model: a group must not smuggle a high-risk finding past the
// approval it needs alone. The batch takes the highest member tier (never
// below peer), the union of every member's exclusions (asset owners of any
// member) and only approvers eligible for every member; each member keeps its
// own acceptance cap (an end past a member's cap is shortened for that member
// and shown in the preview). The caller must have every member in their data
// scope to request, approve or reject. Member requests cannot be decided one
// by one, and once applied each is an ordinary decision with its own expiry
// and material-change check.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"

	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
)

// batchStore stores group exceptions (*postgres.FindingApprovalRepository).
type batchStore interface {
	PendingBatchForSource(ctx context.Context, tenantID shared.ID, sourceType string, sourceID shared.ID) (bool, error)
	PendingFindingIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]bool, error)
	CreateBatch(ctx context.Context, b *vulnerability.ApprovalBatch, members []*vulnerability.Approval) error
	GetBatch(ctx context.Context, tenantID, id shared.ID) (*vulnerability.ApprovalBatch, error)
	ListBatches(ctx context.Context, tenantID shared.ID, status string, source *shared.ID, scope *shared.DataScope, page pagination.Pagination) (pagination.Result[*vulnerability.ApprovalBatch], error)
	BatchMembers(ctx context.Context, tenantID, batchID shared.ID) ([]vulnerability.ApprovalBatchMember, error)
	BatchSignoffs(ctx context.Context, tenantID, batchID shared.ID) ([]approvalpolicy.Signoff, error)
	SignOffBatch(ctx context.Context, tenantID, batchID, signer shared.ID, rec SignoffRecord,
		decide func(prior []approvalpolicy.Signoff) (bool, error),
		finish func(a *vulnerability.Approval) (*vulnerability.FindingActivity, bool, error),
	) (*vulnerability.ApprovalBatch, int, []shared.ID, error)
	CloseBatch(ctx context.Context, tenantID, batchID, actor shared.ID, status vulnerability.ApprovalStatus, reason string) (*vulnerability.ApprovalBatch, error)
}

// ErrGroupExceptionPending: the task already has a pending exception;
// decide or cancel it first.
var ErrGroupExceptionPending = fmt.Errorf("%w: this task already has a pending exception; decide or cancel it first", shared.ErrConflict)

// ErrBatchesUnavailable: group exceptions are not wired.
var ErrBatchesUnavailable = fmt.Errorf("%w: group exceptions are not available", shared.ErrValidation)

func (s *VulnerabilityService) batches() (batchStore, error) {
	b, ok := s.approvalRepo.(batchStore)
	if !ok {
		return nil, ErrBatchesUnavailable
	}
	return b, nil
}

// GroupExceptionInput asks for one exception over a set of findings (the open
// findings of a remediation task).
type GroupExceptionInput struct {
	TenantID        shared.ID
	SourceType      string
	SourceID        shared.ID
	FindingIDs      []shared.ID
	RequestedStatus string
	ClosureReason   string
	Justification   string
	ExpiresAt       *time.Time
	RequestedBy     shared.ID
}

// Skip reasons of a member left out of a group exception.
const (
	GroupSkipNotFound       = "not_found"
	GroupSkipCannotMove     = "cannot_move"
	GroupSkipPendingRequest = "pending_request"
)

// GroupExceptionMember is one finding of a group exception and how it is
// decided.
type GroupExceptionMember struct {
	FindingID shared.ID
	Title     string
	Severity  string
	Tier      string
	RiskClass string
	// End is the member's acceptance end (accepted only): the requested end,
	// or that member's cap when shorter (Shortened).
	End       *time.Time
	Shortened bool
	// Skipped says why the member is left out ("" when included).
	Skipped string
}

// GroupExceptionPreview is what a group exception would be.
type GroupExceptionPreview struct {
	Result   approvalpolicy.Result
	Members  []GroupExceptionMember
	Included int
	Skipped  int
}

// memberPlan is one included member with its evaluation.
type memberPlan struct {
	f   *vulnerability.Finding
	ev  policyEvaluation
	end *time.Time
}

// planGroupException evaluates every member and the group.
func (s *VulnerabilityService) planGroupException(ctx context.Context, in GroupExceptionInput, store batchStore) (*GroupExceptionPreview, []memberPlan, vulnerability.ClosureReason, error) {
	status := vulnerability.FindingStatus(in.RequestedStatus)
	kind, ok := kindOfStatus(status)
	if !ok {
		return nil, nil, "", fmt.Errorf("%w: requested_status must be accepted or false_positive", shared.ErrValidation)
	}
	reason, err := vulnerability.ParseClosureReason(status, in.ClosureReason)
	if err != nil {
		return nil, nil, "", err
	}
	if reason == "" {
		return nil, nil, "", fmt.Errorf("%w: closure_reason is required: one of %v", shared.ErrValidation, vulnerability.PersonClosureReasons(status))
	}
	if pending, err := store.PendingBatchForSource(ctx, in.TenantID, in.SourceType, in.SourceID); err != nil {
		return nil, nil, "", err
	} else if pending {
		return nil, nil, "", ErrGroupExceptionPending
	}
	if len(in.FindingIDs) == 0 {
		return nil, nil, "", fmt.Errorf("%w: the task has no open finding", shared.ErrValidation)
	}
	if len(in.FindingIDs) > vulnerability.MaxApprovalBatchMembers {
		return nil, nil, "", fmt.Errorf("%w: one exception covers at most %d findings; split the task", shared.ErrValidation, vulnerability.MaxApprovalBatchMembers)
	}
	now := time.Now()
	if status == vulnerability.FindingStatusAccepted {
		if in.ExpiresAt != nil {
			if _, err := vulnerability.DecisionEnd(status, in.ExpiresAt, now); err != nil {
				return nil, nil, "", err
			}
		}
	} else if in.ExpiresAt != nil {
		return nil, nil, "", fmt.Errorf("%w: a false positive takes no end", shared.ErrValidation)
	}
	pending, err := store.PendingFindingIDs(ctx, in.TenantID, in.FindingIDs)
	if err != nil {
		return nil, nil, "", err
	}
	preview := &GroupExceptionPreview{}
	plans := make([]memberPlan, 0, len(in.FindingIDs))
	results := make([]approvalpolicy.Result, 0, len(in.FindingIDs))
	var org orgPolicy
	for _, fid := range in.FindingIDs {
		m := GroupExceptionMember{FindingID: fid}
		f, err := s.findingRepo.GetByID(ctx, in.TenantID, fid)
		if err != nil {
			m.Skipped = GroupSkipNotFound
			preview.Members = append(preview.Members, m)
			continue
		}
		// Every member must be the caller's to decide on (the task route
		// checks the same for restricted members).
		if err := s.assertFindingScope(ctx, f); err != nil {
			return nil, nil, "", err
		}
		m.Title, m.Severity = f.Title(), string(f.Severity())
		d := vulnerability.EvaluateTransition(transitionFactsOf(f), personActor(in.RequestedBy, TransitionPermissions{Write: true}), status)
		switch {
		case d.Mode != vulnerability.TransitionRequest || !d.Allowed:
			m.Skipped = GroupSkipCannotMove
		case pending[fid]:
			m.Skipped = GroupSkipPendingRequest
		}
		if m.Skipped != "" {
			preview.Members = append(preview.Members, m)
			continue
		}
		ev, err := s.evaluateFindingRequest(ctx, f, kind, in.RequestedBy, false, false, in.RequestedBy)
		if err != nil {
			return nil, nil, "", err
		}
		org = ev.org
		m.Tier, m.RiskClass = string(ev.result.Tier), string(ev.result.Class)
		var end *time.Time
		if status == vulnerability.FindingStatusAccepted {
			end, m.Shortened = memberEnd(in.ExpiresAt, now, ev.result.MaxAcceptance)
			m.End = end
		}
		plans = append(plans, memberPlan{f: f, ev: ev, end: end})
		results = append(results, ev.result)
		preview.Members = append(preview.Members, m)
	}
	preview.Included = len(plans)
	preview.Skipped = len(preview.Members) - preview.Included
	if preview.Included == 0 {
		return preview, nil, reason, fmt.Errorf("%w: no finding of this task can take this exception", shared.ErrValidation)
	}
	preview.Result = approvalpolicy.Combine(org.policy, org.poolConfigured, results)
	return preview, plans, reason, nil
}

// memberEnd is a member's acceptance end: the requested end (or the 90-day
// default), shortened to the member's cap.
func memberEnd(requested *time.Time, now time.Time, limit time.Duration) (*time.Time, bool) {
	end := now.Add(vulnerability.DefaultAcceptanceDuration)
	if requested != nil {
		end = *requested
	}
	if max := now.Add(limit); end.After(max) {
		return &max, true
	}
	return &end, false
}

// PreviewGroupException answers how a group exception would be decided:
// the group tier, the members with their tier and end, and the members left
// out.
func (s *VulnerabilityService) PreviewGroupException(ctx context.Context, in GroupExceptionInput) (*GroupExceptionPreview, error) {
	store, err := s.batches()
	if err != nil {
		return nil, err
	}
	preview, _, _, err := s.planGroupException(ctx, in, store)
	if err != nil && preview == nil {
		return nil, err
	}
	return preview, err
}

// GroupExceptionResult is a created group exception.
type GroupExceptionResult struct {
	Batch   *vulnerability.ApprovalBatch
	Preview *GroupExceptionPreview
}

// RequestGroupException creates a group exception: one pending batch and a
// pending member request per included finding, in one transaction.
func (s *VulnerabilityService) RequestGroupException(ctx context.Context, in GroupExceptionInput) (*GroupExceptionResult, error) {
	store, err := s.batches()
	if err != nil {
		return nil, err
	}
	preview, plans, reason, err := s.planGroupException(ctx, in, store)
	if err != nil {
		return nil, err
	}
	res := preview.Result
	if n := len([]rune(strings.TrimSpace(in.Justification))); n < res.MinNoteLength || n == 0 {
		return nil, fmt.Errorf("%w: this exception needs a note of at least %d characters (%s tier)", shared.ErrValidation, max(res.MinNoteLength, 1), res.Tier)
	}
	now := time.Now()
	status := vulnerability.FindingStatus(in.RequestedStatus)
	b := &vulnerability.ApprovalBatch{
		ID: shared.NewID(), TenantID: in.TenantID, SourceType: in.SourceType, SourceID: in.SourceID,
		RequestedStatus: status, ClosureReason: reason, Justification: strings.TrimSpace(in.Justification),
		RequestedBy: in.RequestedBy, Tier: string(res.Tier), RiskClass: string(res.Class), RequiredApprovals: res.Required,
		PolicyEval: policyEvalJSON(res), Status: vulnerability.ApprovalStatusPending, DecideBy: now.Add(res.DecideWithin),
		MemberCount: len(plans), CreatedAt: now, Version: 1,
	}
	if status == vulnerability.FindingStatusAccepted {
		end := now.Add(vulnerability.DefaultAcceptanceDuration)
		if in.ExpiresAt != nil {
			end = *in.ExpiresAt
		}
		b.ExpiresAt = &end
	}
	members := make([]*vulnerability.Approval, 0, len(plans))
	for _, p := range plans {
		a := vulnerability.NewApproval(in.TenantID, p.f.ID(), in.RequestedBy, in.RequestedStatus, b.Justification, p.end)
		a.ClosureReason = reason
		a.BatchID = &b.ID
		a.Tier, a.RiskClass, a.RequiredApprovals = string(res.Tier), string(p.ev.result.Class), res.Required
		a.PolicyEval = policyEvalJSON(p.ev.result)
		decideBy := b.DecideBy
		a.DecideBy = &decideBy
		members = append(members, a)
	}
	if err := store.CreateBatch(ctx, b, members); err != nil {
		return nil, err
	}
	s.notifyBatchApprovers(ctx, b, res)
	return &GroupExceptionResult{Batch: b, Preview: preview}, nil
}

// notifyBatchApprovers tells the people who may decide a group exception
// (in-app; the task title and the count, never the note).
func (s *VulnerabilityService) notifyBatchApprovers(ctx context.Context, b *vulnerability.ApprovalBatch, res approvalpolicy.Result) {
	if s.approvalInApp == nil {
		return
	}
	title := fmt.Sprintf("Group exception requested: %s for %d finding(s)", statusLabel(string(b.RequestedStatus)), b.MemberCount)
	for _, uid := range res.Eligible {
		u := uid
		if err := s.approvalInApp.Notify(ctx, notificationdom.NotificationParams{
			TenantID: b.TenantID, Audience: notificationdom.AudienceUser, AudienceID: &u,
			NotificationType: notificationdom.TypeFindingApproval, Title: title,
			Body:     fmt.Sprintf("Tier %s, %d approval(s) needed.", res.Tier, res.Required),
			Severity: notificationdom.SeverityMedium, ResourceType: "approval_batch", ResourceID: &b.ID, URL: approvalInboxURL,
		}); err != nil {
			s.logger.Warn("group exception: in-app notification", "error", logger.SanitizeError(err))
		}
	}
}

// GroupExceptionDecision is the outcome of an approval of a group exception.
type GroupExceptionDecision struct {
	Batch *vulnerability.ApprovalBatch
	// Applied members; Canceled members whose finding had moved.
	Applied  int
	Canceled []shared.ID
	// Shortened: members whose end was cut to their cap at decision time.
	Shortened int
}

// batchMembersInScope loads the batch's pending members and checks that the
// caller has every one in their data scope.
func (s *VulnerabilityService) batchMembersInScope(ctx context.Context, store batchStore, b *vulnerability.ApprovalBatch) ([]*vulnerability.Finding, error) {
	members, err := store.BatchMembers(ctx, b.TenantID, b.ID)
	if err != nil {
		return nil, err
	}
	out := make([]*vulnerability.Finding, 0, len(members))
	for _, m := range members {
		if err := s.dataScope.AssertFinding(ctx, b.TenantID, m.FindingID); err != nil {
			return nil, err
		}
		if m.Status != vulnerability.ApprovalStatusPending {
			continue
		}
		f, err := s.findingRepo.GetByID(ctx, b.TenantID, m.FindingID)
		if err != nil {
			continue // deleted since: the member is canceled at decision
		}
		out = append(out, f)
	}
	return out, nil
}

// ApproveGroupException records approver's approval of a group exception
// under the policy evaluated now; the last required approval applies every
// member (each with its own end) in one transaction.
func (s *VulnerabilityService) ApproveGroupException(ctx context.Context, tenantID, batchID, approver shared.ID) (*GroupExceptionDecision, error) {
	store, err := s.batches()
	if err != nil {
		return nil, err
	}
	b, err := store.GetBatch(ctx, tenantID, batchID)
	if err != nil {
		return nil, err
	}
	if b.Status != vulnerability.ApprovalStatusPending {
		return nil, vulnerability.ErrBatchNotPending
	}
	if !b.RequestedBy.IsZero() && b.RequestedBy == approver {
		return nil, vulnerability.ErrSelfApproval
	}
	findings, err := s.batchMembersInScope(ctx, store, b)
	if err != nil {
		return nil, err
	}
	prior, err := store.BatchSignoffs(ctx, tenantID, batchID)
	if err != nil {
		return nil, err
	}
	known := []shared.ID{approver}
	for _, p := range prior {
		known = append(known, p.UserID)
	}
	kind, _ := kindOfStatus(b.RequestedStatus)
	now := time.Now()
	type memberNow struct {
		f     *vulnerability.Finding
		end   *time.Time
		facts approvalpolicy.Facts
	}
	byFinding := map[shared.ID]memberNow{}
	results := make([]approvalpolicy.Result, 0, len(findings))
	var org orgPolicy
	shortened := 0
	for _, f := range findings {
		ev, err := s.evaluateFindingRequest(ctx, f, kind, b.RequestedBy, false, false, known...)
		if err != nil {
			return nil, err
		}
		org = ev.org
		results = append(results, ev.result)
		mn := memberNow{f: f, facts: ev.facts}
		if kind == approvalpolicy.KindAccepted {
			end, cut := memberEnd(b.ExpiresAt, now, ev.result.MaxAcceptance)
			if cut {
				shortened++
			}
			mn.end = end
		}
		byFinding[f.ID()] = mn
	}
	res := approvalpolicy.Combine(org.policy, org.poolConfigured, results)
	// The group is never decided below its tier at request time.
	if t := approvalpolicy.Tier(b.Tier); t.IsValid() && t.Rank() > res.Tier.Rank() {
		res.Tier, res.Required = t, t.RequiredApprovals()
		res.SecurityPool, res.StepUp = t.NeedsSecurityPool(), res.StepUp || t.NeedsStepUp()
	}
	if _, err := res.Sign(approver, prior); err != nil {
		return nil, err
	}
	if res.StepUp {
		if err := s.requireApproverStepUp(ctx, approver); err != nil {
			return nil, err
		}
	}
	rec := SignoffRecord{UserID: approver, PoolFallback: res.PoolFallback, StepUp: res.StepUp}
	for _, id := range res.EligiblePool {
		rec.SecurityPool = rec.SecurityPool || id == approver
	}
	finish := func(a *vulnerability.Approval) (*vulnerability.FindingActivity, bool, error) {
		mn, ok := byFinding[a.FindingID]
		if !ok {
			return nil, false, nil
		}
		// The finding may have moved since: it must still be able to make
		// the move.
		if d := vulnerability.EvaluateTransition(transitionFactsOf(mn.f), personActor(approver, TransitionPermissions{Write: true}),
			b.RequestedStatus); d.Mode != vulnerability.TransitionRequest || !d.Allowed {
			return nil, false, nil
		}
		if kind == approvalpolicy.KindAccepted {
			if mn.end == nil || !mn.end.After(now) {
				return nil, false, nil
			}
			a.ExpiresAt = mn.end
		}
		a.DecisionFacts = factsJSON(mn.facts)
		if err := a.Approve(approver); err != nil {
			return nil, false, err
		}
		entry, err := vulnerability.NewFindingActivity(a.TenantID, a.FindingID, vulnerability.ActivityApprovalApproved,
			&approver, vulnerability.ActorTypeUser, map[string]any{
				"approval_id": a.ID.String(), "batch_id": b.ID.String(), "requested_status": a.RequestedStatus,
				"approved_by": approver.String(), "tier": string(res.Tier),
			}, vulnerability.SourceAPI, nil)
		return entry, err == nil, err
	}
	out, applied, canceled, err := store.SignOffBatch(ctx, tenantID, batchID, approver, rec,
		func(prior []approvalpolicy.Signoff) (bool, error) { return res.Sign(approver, prior) }, finish)
	if err != nil {
		return nil, err
	}
	out.RequiredApprovals = res.Required
	return &GroupExceptionDecision{Batch: out, Applied: applied, Canceled: canceled, Shortened: shortened}, nil
}

// RejectGroupException rejects a pending group exception (an approver with
// every member in scope); CancelGroupException cancels it (its requester).
func (s *VulnerabilityService) RejectGroupException(ctx context.Context, tenantID, batchID, by shared.ID, reason string) (*vulnerability.ApprovalBatch, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("%w: a rejection needs a reason", shared.ErrValidation)
	}
	return s.closeGroupException(ctx, tenantID, batchID, by, vulnerability.ApprovalStatusRejected, strings.TrimSpace(reason))
}

// CancelGroupException cancels a pending group exception; only its
// requester may.
func (s *VulnerabilityService) CancelGroupException(ctx context.Context, tenantID, batchID, by shared.ID) (*vulnerability.ApprovalBatch, error) {
	return s.closeGroupException(ctx, tenantID, batchID, by, vulnerability.ApprovalStatusCanceled, "")
}

func (s *VulnerabilityService) closeGroupException(ctx context.Context, tenantID, batchID, by shared.ID, status vulnerability.ApprovalStatus, reason string) (*vulnerability.ApprovalBatch, error) {
	store, err := s.batches()
	if err != nil {
		return nil, err
	}
	b, err := store.GetBatch(ctx, tenantID, batchID)
	if err != nil {
		return nil, err
	}
	if _, err := s.batchMembersInScope(ctx, store, b); err != nil {
		return nil, err
	}
	if status == vulnerability.ApprovalStatusCanceled && (b.RequestedBy.IsZero() || b.RequestedBy != by) {
		return nil, fmt.Errorf("%w: only the requester can cancel a group exception", shared.ErrForbidden)
	}
	return store.CloseBatch(ctx, tenantID, batchID, by, status, reason)
}

// GetGroupException reads a group exception and its members; the caller
// must have every member in their data scope.
func (s *VulnerabilityService) GetGroupException(ctx context.Context, tenantID, batchID shared.ID) (*vulnerability.ApprovalBatch, []vulnerability.ApprovalBatchMember, error) {
	store, err := s.batches()
	if err != nil {
		return nil, nil, err
	}
	b, err := store.GetBatch(ctx, tenantID, batchID)
	if err != nil {
		return nil, nil, err
	}
	members, err := store.BatchMembers(ctx, tenantID, batchID)
	if err != nil {
		return nil, nil, err
	}
	for _, m := range members {
		if err := s.dataScope.AssertFinding(ctx, tenantID, m.FindingID); err != nil {
			return nil, nil, err
		}
	}
	return b, members, nil
}

// ListGroupExceptions lists the tenant's group exceptions the caller may see,
// optionally of one source (a remediation task id).
func (s *VulnerabilityService) ListGroupExceptions(ctx context.Context, tenantID shared.ID, status, sourceID string, page pagination.Pagination) (pagination.Result[*vulnerability.ApprovalBatch], error) {
	store, err := s.batches()
	if err != nil {
		return pagination.Result[*vulnerability.ApprovalBatch]{}, err
	}
	if status != "" {
		if _, ok := vulnerability.ParseApprovalStatus(status); !ok {
			return pagination.Result[*vulnerability.ApprovalBatch]{}, fmt.Errorf("%w: invalid status %q", shared.ErrValidation, status)
		}
	}
	var source *shared.ID
	if sourceID != "" {
		id, err := shared.IDFromString(sourceID)
		if err != nil {
			return pagination.Result[*vulnerability.ApprovalBatch]{}, fmt.Errorf("%w: source_id must be an id", shared.ErrValidation)
		}
		source = &id
	}
	scope, err := s.dataScope.Resolve(ctx, tenantID)
	if err != nil {
		return pagination.Result[*vulnerability.ApprovalBatch]{}, fmt.Errorf("failed to resolve data scope: %w", err)
	}
	return store.ListBatches(ctx, tenantID, status, source, scope, page)
}
