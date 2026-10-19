package finding

// Analyst severity override (docs/architecture/finding-severity-override.md).
//
// A person changes a finding's effective severity with a reason; the tools'
// severity is kept as the source severity and a later scan never reverts the
// decision. The change recomputes the finding's priority class, its reason
// and its SLA deadline at once, with the same classifier and SLA applier the
// ingest path and the finding-priority worker use, and the response carries
// them.
//
// Threat model: lowering a severity hides risk the same way a false positive
// does (it lowers the priority, the SLA urgency and the dashboards). So:
//   - the route needs findings:severity and the finding must be in the
//     caller's data scope (404 otherwise); the tenant comes from the
//     authenticated context;
//   - a reason is always required; every change, request and decision is on
//     the finding's timeline and in the audit log with the old and new
//     severity and the reason;
//   - a DOWNGRADE of the effective severity goes through the organization's
//     false-positive approval policy (level all / high_and_above / off and
//     the policy tiers): when the requester may not decide it alone it becomes
//     a pending request that another eligible person approves (never the
//     requester, never an owner of the finding's asset, step-up when the
//     tier asks for it), evaluated again on the facts at approval time and
//     applied only while the finding still has the severity it was requested
//     from;
//   - an upgrade needs no approval (it only makes the finding more urgent);
//   - restoring the reported severity is a change like any other: when it
//     lowers the effective severity it follows the downgrade rule.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/internal/app/activity"
	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SetSeverityRequestRepository wires the store of severity requests. Without
// it a downgrade that needs approval is refused (fail closed).
func (s *VulnerabilityService) SetSeverityRequestRepository(r vulnerability.SeverityRequestRepository) {
	s.severityRequests = r
}

// ChangeSeverityInput is one change of a finding's effective severity.
type ChangeSeverityInput struct {
	TenantID  string
	FindingID string
	ActorID   string
	// Severity is the new effective severity; ignored with Restore.
	Severity string
	// Restore ends the analyst override: the reported severity applies.
	Restore bool
	Reason  string
	// CanApprove: the caller holds findings:approve (the policy's single
	// tier is open only to them).
	CanApprove bool
	Audit      audit.AuditContext
}

// SeverityChangeResult is the outcome of a severity change: the finding as it
// is now and, when the change waits for approval, the pending request.
type SeverityChangeResult struct {
	Finding *vulnerability.Finding
	Applied bool
	Request *vulnerability.SeverityRequest
}

// ErrSeverityRequestsUnavailable: a downgrade needs approval and the request
// store is not wired.
var ErrSeverityRequestsUnavailable = fmt.Errorf("%w: severity changes that need approval are not available", shared.ErrNotImplemented)

// severityWriter is the narrow writer of severity decisions
// (*postgres.FindingRepository).
func (s *VulnerabilityService) severityWriter() (vulnerability.SeverityWriter, error) {
	w, ok := s.findingRepo.(vulnerability.SeverityWriter)
	if !ok {
		return nil, fmt.Errorf("%w: severity decisions are not available", shared.ErrNotImplemented)
	}
	return w, nil
}

// ChangeFindingSeverity changes a finding's effective severity: at once for
// an upgrade or a downgrade the requester may decide alone, otherwise as a
// pending request.
func (s *VulnerabilityService) ChangeFindingSeverity(ctx context.Context, in ChangeSeverityInput) (*SeverityChangeResult, error) {
	f, err := s.getFindingWithTenantCheck(ctx, in.FindingID, in.TenantID)
	if err != nil {
		return nil, err
	}
	actor, err := shared.IDFromString(in.ActorID)
	if err != nil {
		return nil, fmt.Errorf("%w: a severity change needs an authenticated person", shared.ErrValidation)
	}
	if in.Audit.ActorID == "" {
		in.Audit.ActorID = in.ActorID
	}
	reason, err := vulnerability.NormalizeSeverityReason(in.Reason)
	if err != nil {
		return nil, err
	}
	target, err := severityTarget(f, in.Restore, in.Severity)
	if err != nil {
		return nil, err
	}
	if target == f.Severity() && !in.Restore {
		// The severity is already this one: nothing to decide.
		return &SeverityChangeResult{Finding: f, Applied: true}, nil
	}
	if s.severityRequests != nil {
		pending, err := s.severityRequests.Pending(ctx, f.TenantID(), f.ID())
		if err != nil {
			return nil, err
		}
		if pending != nil {
			return nil, vulnerability.ErrPendingRequestExists
		}
	}

	if vulnerability.IsSeverityDowngrade(f.Severity(), target) {
		ev, err := s.evaluateFindingRequest(ctx, f, approvalpolicy.KindFalsePositive, actor, false, in.CanApprove)
		if err != nil {
			return nil, err
		}
		if !ev.result.SinglePerson() {
			if n := utf8.RuneCountInString(reason); n < ev.result.MinNoteLength {
				return nil, fmt.Errorf("%w: this change needs a reason of at least %d characters (%s tier)",
					shared.ErrValidation, ev.result.MinNoteLength, ev.result.Tier)
			}
			req, err := s.requestSeverityChange(ctx, f, target, in.Restore, reason, actor, ev, in.Audit)
			if err != nil {
				return nil, err
			}
			return &SeverityChangeResult{Finding: f, Request: req}, nil
		}
	}

	expected := f.Severity()
	if err := s.applySeverityDecision(ctx, f, target, in.Restore, reason, actor, expected); err != nil {
		return nil, err
	}
	s.recordSeverityChanged(ctx, f, expected, reason, actor, nil, in.Audit)
	return &SeverityChangeResult{Finding: f, Applied: true}, nil
}

// severityTarget is the effective severity a change asks for.
func severityTarget(f *vulnerability.Finding, restore bool, sev string) (vulnerability.Severity, error) {
	if restore {
		if !f.HasSeverityOverride() {
			return "", fmt.Errorf("%w: the finding has no analyst severity to restore from", shared.ErrValidation)
		}
		return f.SourceSeverity(), nil
	}
	target, err := vulnerability.ParseSeverity(sev)
	if err != nil {
		return "", fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}
	return target, nil
}

// setSeverity applies the decision to f in memory.
func setSeverity(f *vulnerability.Finding, target vulnerability.Severity, restore bool, reason string, by shared.ID, now time.Time) error {
	if restore {
		f.RestoreSourceSeverity()
		return nil
	}
	_, err := f.SetSeverityOverride(target, reason, by, now)
	return err
}

// applySeverityDecision sets the severity on f (override or restore),
// recomputes the priority class, its reason and the SLA deadline of an open
// finding with the shared classifier and SLA applier (closed findings keep
// what they had when they closed, as the finding-priority worker does), and
// persists it all in one statement, guarded on the severity the decision was
// made from.
func (s *VulnerabilityService) applySeverityDecision(ctx context.Context, f *vulnerability.Finding, target vulnerability.Severity,
	restore bool, reason string, by shared.ID, expected vulnerability.Severity,
) error {
	w, err := s.severityWriter()
	if err != nil {
		return err
	}
	if err := setSeverity(f, target, restore, reason, by, time.Now()); err != nil {
		return err
	}
	downgrade := vulnerability.IsSeverityDowngrade(expected, f.Severity())
	s.recomputePriority(ctx, f, downgrade)
	return w.SaveSeverityDecision(ctx, f, expected, downgrade)
}

// slaRelaxer moves a deadline later for an approved severity downgrade
// (*sla.Applier).
type slaRelaxer interface {
	RelaxForDecision(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) error
}

// recomputePriority reclassifies an open finding in memory (priority class,
// reason, reachability, EPSS/KEV) and recomputes its SLA deadline: the same
// classifier and SLA applier as ingest and the finding-priority worker. Those
// only ever tighten a deadline; a downgrade the approval policy allowed is the
// explicit decision that may extend it, to the new class's window counted
// from the first detection (never from now: the clock does not restart).
func (s *VulnerabilityService) recomputePriority(ctx context.Context, f *vulnerability.Finding, downgrade bool) {
	if !vulnerability.IsOpenStatus(f.Status()) {
		return
	}
	s.enrichAndClassifyFinding(ctx, f)
	if !downgrade {
		return
	}
	if r, ok := s.slaApplier.(slaRelaxer); ok {
		if err := r.RelaxForDecision(ctx, f.TenantID(), []*vulnerability.Finding{f}); err != nil {
			s.logger.Warn("severity decision: sla deadline", "finding_id", f.ID().String(), "error", err)
		}
	}
}

// requestSeverityChange stores a downgrade that waits for approval, records
// it and tells the people who may approve it.
func (s *VulnerabilityService) requestSeverityChange(ctx context.Context, f *vulnerability.Finding, target vulnerability.Severity,
	restore bool, reason string, actor shared.ID, ev policyEvaluation, actx audit.AuditContext,
) (*vulnerability.SeverityRequest, error) {
	if s.severityRequests == nil {
		return nil, ErrSeverityRequestsUnavailable
	}
	now := time.Now().UTC()
	within := ev.result.DecideWithin
	if within <= 0 {
		within = vulnerability.DefaultDecisionWindow
	}
	required := ev.result.Required
	if required < 1 {
		required = 1
	}
	by := actor
	req := &vulnerability.SeverityRequest{
		ID: shared.NewID(), TenantID: f.TenantID(), FindingID: f.ID(),
		RequestedSeverity: target, PreviousSeverity: f.Severity(), Restore: restore,
		Reason: reason, RequestedBy: &by, Status: vulnerability.ApprovalStatusPending,
		Tier: string(ev.result.Tier), RequiredApprovals: required,
		DecideBy: now.Add(within), CreatedAt: now,
	}
	if err := s.severityRequests.Create(ctx, req); err != nil {
		return nil, err
	}
	s.recordSeverityActivity(ctx, f, vulnerability.ActivitySeverityChangeRequested, &actor, map[string]any{
		"request_id":         req.ID.String(),
		"old_severity":       req.PreviousSeverity.String(),
		"requested_severity": target.String(),
		"source_severity":    f.SourceSeverity().String(),
		"restore":            restore,
		"reason":             reason,
		"tier":               req.Tier,
		"approvals_required": required,
	})
	s.auditSeverity(ctx, actx, auditdom.ActionFindingSeverityRequested, f, "Requested a lower severity for a finding",
		map[string]any{
			"request_id": req.ID.String(), "old_severity": req.PreviousSeverity.String(),
			"requested_severity": target.String(), "restore": restore, "reason": reason, "tier": req.Tier,
		})
	s.notifySeverityApprovers(ctx, f, req, ev.result.Eligible)
	return req, nil
}

// notifySeverityApprovers tells the people the policy lets decide the
// request (in-app; never the requester or an owner of the asset).
func (s *VulnerabilityService) notifySeverityApprovers(ctx context.Context, f *vulnerability.Finding, req *vulnerability.SeverityRequest, eligible []shared.ID) {
	if s.approvalInApp == nil {
		return
	}
	title := "Severity change waiting for approval"
	body := fmt.Sprintf("%s: %s to %s", oneLineTitle(findingDisplayTitle(f)), req.PreviousSeverity, req.RequestedSeverity)
	url := "/findings/" + f.ID().String()
	for _, uid := range eligible {
		if req.RequestedBy != nil && uid == *req.RequestedBy {
			continue
		}
		user := uid
		fid := f.ID()
		if err := s.approvalInApp.Notify(ctx, notificationdom.NotificationParams{
			TenantID: f.TenantID(), Audience: notificationdom.AudienceUser, AudienceID: &user,
			NotificationType: notificationdom.TypeFindingApproval, Title: title, Body: body,
			Severity: notificationdom.SeverityMedium, ResourceType: "finding", ResourceID: &fid, URL: url,
		}); err != nil {
			s.logger.Warn("severity request: in-app notification", "error", logger.SanitizeError(err))
		}
	}
}

func findingDisplayTitle(f *vulnerability.Finding) string {
	if t := strings.TrimSpace(f.Title()); t != "" {
		return t
	}
	return f.Message()
}

// DecideSeverityRequestInput names one severity request and who decides it.
type DecideSeverityRequestInput struct {
	TenantID  string
	FindingID string
	RequestID string
	ActorID   string
	// Note is the reason of a rejection.
	Note  string
	Audit audit.AuditContext
}

// loadSeverityRequest returns the finding (in the caller's data scope) and
// its request; a request of another finding or tenant is not found.
func (s *VulnerabilityService) loadSeverityRequest(ctx context.Context, in *DecideSeverityRequestInput) (*vulnerability.Finding, *vulnerability.SeverityRequest, shared.ID, error) {
	if in.Audit.ActorID == "" {
		in.Audit.ActorID = in.ActorID
	}
	if s.severityRequests == nil {
		return nil, nil, shared.ID{}, ErrSeverityRequestsUnavailable
	}
	f, err := s.getFindingWithTenantCheck(ctx, in.FindingID, in.TenantID)
	if err != nil {
		return nil, nil, shared.ID{}, err
	}
	actor, err := shared.IDFromString(in.ActorID)
	if err != nil {
		return nil, nil, shared.ID{}, fmt.Errorf("%w: a decision needs an authenticated person", shared.ErrValidation)
	}
	rid, err := shared.IDFromString(in.RequestID)
	if err != nil {
		return nil, nil, shared.ID{}, fmt.Errorf("%w: invalid request id", shared.ErrValidation)
	}
	req, err := s.severityRequests.Get(ctx, f.TenantID(), rid)
	if err != nil {
		return nil, nil, shared.ID{}, err
	}
	if req.FindingID != f.ID() {
		return nil, nil, shared.ID{}, fmt.Errorf("%w: severity request not found", shared.ErrNotFound)
	}
	return f, req, actor, nil
}

// ApproveSeverityRequest records the caller's approval of a pending severity
// request under the policy evaluated now and applies the change when it is
// the last approval needed. The route needs findings:approve.
func (s *VulnerabilityService) ApproveSeverityRequest(ctx context.Context, in DecideSeverityRequestInput) (*SeverityChangeResult, error) {
	f, req, approver, err := s.loadSeverityRequest(ctx, &in)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if req.Status != vulnerability.ApprovalStatusPending {
		return nil, fmt.Errorf("%w: this request is %s", shared.ErrConflict, req.Status)
	}
	if !req.IsDecidable(now) {
		return nil, vulnerability.ErrDecisionOverdue
	}
	if req.RequestedBy != nil && *req.RequestedBy == approver {
		return nil, vulnerability.ErrSelfApproval
	}
	if f.Severity() != req.PreviousSeverity {
		return nil, vulnerability.ErrSeverityRequestStale
	}
	prior, err := s.severityRequests.Signoffs(ctx, f.TenantID(), req.ID)
	if err != nil {
		return nil, err
	}
	known := []shared.ID{approver}
	for _, p := range prior {
		known = append(known, p.UserID)
	}
	requester := shared.ID{}
	if req.RequestedBy != nil {
		requester = *req.RequestedBy
	}
	ev, err := s.evaluateFindingRequest(ctx, f, approvalpolicy.KindFalsePositive, requester, false, false, known...)
	if err != nil {
		return nil, err
	}
	res := ev.result
	if res.Tier == approvalpolicy.TierSingle {
		// The policy relaxed since the request: one other eligible person
		// still decides it (it was made as a request).
		res.Tier, res.Required = approvalpolicy.TierPeer, 1
	}
	if _, err := res.Sign(approver, prior); err != nil {
		return nil, err
	}
	if res.StepUp {
		if err := s.requireApproverStepUp(ctx, approver); err != nil {
			return nil, err
		}
	}
	w, err := s.severityWriter()
	if err != nil {
		return nil, err
	}
	// The override's author is the requester (whose decision it is); the
	// approver is on the request and the timeline.
	author := approver
	if req.RequestedBy != nil {
		author = *req.RequestedBy
	}
	rec := vulnerability.SeveritySignoff{UserID: approver, PoolFallback: res.PoolFallback, StepUp: res.StepUp}
	for _, id := range res.EligiblePool {
		rec.SecurityPool = rec.SecurityPool || id == approver
	}
	applied, err := s.severityRequests.SignOff(ctx, f.TenantID(), req.ID, rec,
		func(prior []approvalpolicy.Signoff) (bool, error) { return res.Sign(approver, prior) },
		func(ctx context.Context, tw vulnerability.SeverityWriter) error {
			// Only the last approval changes the finding.
			if err := setSeverity(f, req.RequestedSeverity, req.Restore, req.Reason, author, now); err != nil {
				return err
			}
			return tw.SaveSeverityDecision(ctx, f, req.PreviousSeverity, false)
		})
	if errors.Is(err, vulnerability.ErrSeverityChangeConflict) {
		return nil, vulnerability.ErrSeverityRequestStale
	}
	if err != nil {
		return nil, err
	}
	if !applied {
		s.recordSeverityActivity(ctx, f, vulnerability.ActivityApprovalSigned, &approver, map[string]any{
			"severity_request_id": req.ID.String(),
			"requested_severity":  req.RequestedSeverity.String(),
			"signed_by":           approver.String(),
			"approvals_required":  res.Required,
		})
		fresh, err := s.findingRepo.GetByID(ctx, f.TenantID(), f.ID())
		if err != nil {
			return nil, err
		}
		pending, err := s.severityRequests.Get(ctx, f.TenantID(), req.ID)
		if err != nil {
			return nil, err
		}
		return &SeverityChangeResult{Finding: fresh, Request: pending}, nil
	}
	// The severity is written; now the priority and SLA computed from it.
	downgrade := vulnerability.IsSeverityDowngrade(req.PreviousSeverity, f.Severity())
	s.recomputePriority(ctx, f, downgrade)
	if err := w.SaveSeverityDecision(ctx, f, f.Severity(), downgrade); err != nil {
		// The decision stands; the finding-priority worker recomputes the
		// class later (the severity change queued the asset).
		s.logger.Warn("severity request: save recomputed priority", "finding_id", f.ID().String(), "error", err)
	}
	s.recordSeverityChanged(ctx, f, req.PreviousSeverity, req.Reason, author, &severityApproval{requestID: req.ID, approvedBy: approver}, in.Audit)
	return &SeverityChangeResult{Finding: f, Applied: true}, nil
}

// RejectSeverityRequest rejects a pending severity request with a note. The
// route needs findings:approve; the requester withdraws instead.
func (s *VulnerabilityService) RejectSeverityRequest(ctx context.Context, in DecideSeverityRequestInput) (*SeverityChangeResult, error) {
	f, req, actor, err := s.loadSeverityRequest(ctx, &in)
	if err != nil {
		return nil, err
	}
	if req.RequestedBy != nil && *req.RequestedBy == actor {
		return nil, fmt.Errorf("%w: withdraw your own request instead of rejecting it", shared.ErrForbidden)
	}
	note, err := vulnerability.NormalizeSeverityReason(in.Note)
	if err != nil {
		return nil, err
	}
	return s.closeSeverityRequest(ctx, f, req, actor, vulnerability.ApprovalStatusRejected, note, nil, in.Audit)
}

// CancelSeverityRequest withdraws the caller's own pending severity request.
func (s *VulnerabilityService) CancelSeverityRequest(ctx context.Context, in DecideSeverityRequestInput) (*SeverityChangeResult, error) {
	f, req, actor, err := s.loadSeverityRequest(ctx, &in)
	if err != nil {
		return nil, err
	}
	if req.RequestedBy == nil || *req.RequestedBy != actor {
		return nil, fmt.Errorf("%w: only the requester withdraws a severity request", shared.ErrForbidden)
	}
	return s.closeSeverityRequest(ctx, f, req, actor, vulnerability.ApprovalStatusCanceled, strings.TrimSpace(in.Note), &actor, in.Audit)
}

func (s *VulnerabilityService) closeSeverityRequest(ctx context.Context, f *vulnerability.Finding, req *vulnerability.SeverityRequest,
	actor shared.ID, status vulnerability.ApprovalStatus, note string, requester *shared.ID, actx audit.AuditContext,
) (*SeverityChangeResult, error) {
	if err := s.severityRequests.Close(ctx, f.TenantID(), req.ID, status, actor, note, requester); err != nil {
		return nil, err
	}
	kind := vulnerability.ActivitySeverityChangeRejected
	if status == vulnerability.ApprovalStatusCanceled {
		kind = vulnerability.ActivitySeverityChangeCanceled
	}
	s.recordSeverityActivity(ctx, f, kind, &actor, map[string]any{
		"request_id":         req.ID.String(),
		"requested_severity": req.RequestedSeverity.String(),
		"note":               note,
	})
	s.auditSeverity(ctx, actx, auditdom.ActionFindingSeverityRequestClosed, f, "Closed a severity request ("+string(status)+")",
		map[string]any{"request_id": req.ID.String(), "status": string(status), "requested_severity": req.RequestedSeverity.String(), "note": note})
	return &SeverityChangeResult{Finding: f}, nil
}

// PendingSeverityRequest returns the finding's pending severity request, or
// nil. The caller has already read the finding under its data scope.
func (s *VulnerabilityService) PendingSeverityRequest(ctx context.Context, tenantID, findingID shared.ID) (*vulnerability.SeverityRequest, error) {
	if s.severityRequests == nil {
		return nil, nil //nolint:nilnil // not wired: no requests
	}
	return s.severityRequests.Pending(ctx, tenantID, findingID)
}

// severityApproval names the approved request behind an applied change.
type severityApproval struct {
	requestID  shared.ID
	approvedBy shared.ID
}

// recordSeverityChanged writes the severity_changed timeline entry and the
// audit event of an applied change.
func (s *VulnerabilityService) recordSeverityChanged(ctx context.Context, f *vulnerability.Finding, old vulnerability.Severity,
	reason string, actor shared.ID, approval *severityApproval, actx audit.AuditContext,
) {
	changes := map[string]any{
		"old_severity":    old.String(),
		"new_severity":    f.Severity().String(),
		"source_severity": f.SourceSeverity().String(),
		"override":        f.HasSeverityOverride(),
		"reason":          reason,
	}
	if pc := f.PriorityClass(); pc != nil {
		changes["priority_class"] = string(*pc)
	}
	if d := f.SLADeadline(); d != nil {
		changes["sla_deadline"] = d.UTC().Format(time.RFC3339)
	}
	actorRef := &actor
	if approval != nil {
		changes["request_id"] = approval.requestID.String()
		changes["approved_by"] = approval.approvedBy.String()
		approver := approval.approvedBy
		actorRef = &approver
	}
	s.recordSeverityActivity(ctx, f, vulnerability.ActivitySeverityChanged, actorRef, changes)
	msg := "Changed a finding's severity"
	if !f.HasSeverityOverride() {
		msg = "Restored a finding's reported severity"
	}
	s.auditSeverity(ctx, actx, auditdom.ActionFindingSeverityChanged, f, msg, changes)
}

func (s *VulnerabilityService) recordSeverityActivity(ctx context.Context, f *vulnerability.Finding, kind vulnerability.ActivityType,
	actor *shared.ID, changes map[string]any,
) {
	if s.activityService == nil {
		return
	}
	var actorID *string
	if actor != nil {
		id := actor.String()
		actorID = &id
	}
	if _, err := s.activityService.RecordActivity(ctx, activity.RecordActivityInput{
		TenantID:     f.TenantID().String(),
		FindingID:    f.ID().String(),
		ActivityType: string(kind),
		ActorID:      actorID,
		ActorType:    string(vulnerability.ActorTypeUser),
		Changes:      changes,
		Source:       string(vulnerability.SourceAPI),
	}); err != nil {
		s.logger.Warn("failed to record severity activity", "type", string(kind), "error", err)
	}
}

func (s *VulnerabilityService) auditSeverity(ctx context.Context, actx audit.AuditContext, action auditdom.Action,
	f *vulnerability.Finding, msg string, meta map[string]any,
) {
	if s.auditService == nil {
		return
	}
	if actx.TenantID == "" {
		actx.TenantID = f.TenantID().String()
	}
	event := audit.NewSuccessEvent(action, auditdom.ResourceTypeFinding, f.ID().String()).
		WithMessage(msg).
		WithSeverity(auditdom.SeverityMedium)
	for k, v := range meta {
		event = event.WithMetadata(k, v)
	}
	if err := s.auditService.LogEvent(ctx, actx, event); err != nil {
		s.logger.Warn("failed to audit severity change", "error", err)
	}
}
