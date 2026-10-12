package scangov

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SubmitInput is a request for approval of a scan's current definition.
type SubmitInput struct {
	Justification string
	Ticket        string
	// RunOnApproval starts a run as the requester once approved (a
	// scheduled scan runs at its schedule either way).
	RunOnApproval bool
}

func (in SubmitInput) validate() error {
	switch {
	case len(in.Justification) > scangov.MaxJustificationLen:
		return fmt.Errorf("%w: justification: at most %d characters", shared.ErrValidation, scangov.MaxJustificationLen)
	case len(in.Ticket) > scangov.MaxTicketLen || strings.ContainsAny(in.Ticket, "\r\n"):
		return fmt.Errorf("%w: ticket: one line of at most %d characters", shared.ErrValidation, scangov.MaxTicketLen)
	}
	return nil
}

// ScanStatus is a scan's approval state as the scan page shows it.
type ScanStatus struct {
	Mode       scangov.Mode
	Evaluation scangov.Evaluation
	// Approved: an approval authorizes the current definition now.
	Approved bool
	Current  *scangov.Request // the approval in force, or the pending request
	// Changes from the last approved definition (a re-approval).
	Changes []scangov.Change
}

// Status answers a scan's approval state.
// viewer is who asks (the requester facts of the rules).
func (s *Service) Status(ctx context.Context, tenantID, scanID shared.ID, viewer string) (*ScanStatus, error) {
	if err := s.requireRepo(); err != nil {
		return nil, err
	}
	if s.scans == nil {
		return nil, fmt.Errorf("%w: scans not wired", shared.ErrInternal)
	}
	sc, def, facts, err := s.scans.GovernanceSubject(ctx, tenantID, scanID)
	if err != nil {
		return nil, err
	}
	ev, err := s.evaluateAt(ctx, tenantID, facts, viewer, plannedAt(sc, s.clock()))
	if err != nil {
		return nil, err
	}
	out := &ScanStatus{Mode: ev.Mode, Evaluation: ev}
	if ev.Mode == scangov.ModeOff {
		return out, nil
	}
	digest, now := def.Digest(), s.clock()
	approved, err := s.repo.ApprovedFor(ctx, tenantID, scanID, digest)
	if err != nil {
		return nil, err
	}
	if approved != nil && approved.Authorizes(digest, now) && satisfies(approved, ev) {
		out.Approved, out.Current = true, approved
		return out, nil
	}
	pending, err := s.repo.Pending(ctx, tenantID, scanID)
	if err != nil {
		return nil, err
	}
	if pending != nil && pending.IsPending(now) {
		out.Current = pending
	}
	last, err := s.repo.LastApproved(ctx, tenantID, scanID)
	if err != nil {
		return nil, err
	}
	if last != nil {
		out.Changes = scangov.Diff(last.Definition, def)
	}
	return out, nil
}

// satisfies reports whether an approval meets the current requirement: an
// emergency always does in its window; otherwise it needs at least as many
// approvals as the rules now ask (switching to Strict needs a second
// approver for scans approved once).
func satisfies(r *scangov.Request, ev scangov.Evaluation) bool {
	return r.Emergency || len(r.Approvals) >= ev.Approvals
}

// Submit asks for approval of the scan's current definition. It is refused
// when the organization's rules do not require one, and when evidence the
// rules ask for is missing. An older pending request of the scan is
// superseded.
func (s *Service) Submit(ctx context.Context, tenantID, scanID shared.ID, in SubmitInput, actor Actor) (*scangov.Request, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	if err := s.requireRepo(); err != nil {
		return nil, err
	}
	if s.scans == nil {
		return nil, fmt.Errorf("%w: scans not wired", shared.ErrInternal)
	}
	sc, def, facts, err := s.scans.GovernanceSubject(ctx, tenantID, scanID)
	if err != nil {
		return nil, err
	}
	m, st, err := s.rules(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if m == scangov.ModeOff {
		return nil, scangov.ErrGovernanceOff
	}
	if facts, err = s.withRequester(ctx, tenantID, st.Rules, facts, actor.UserID, plannedAt(sc, s.clock())); err != nil {
		return nil, err
	}
	ev := scangov.Evaluate(m, st.Rules, facts)
	if !ev.Required {
		return nil, scangov.ErrNotRequired
	}
	now, digest := s.clock(), def.Digest()
	if approved, err := s.repo.ApprovedFor(ctx, tenantID, scanID, digest); err != nil {
		return nil, err
	} else if approved != nil && approved.Authorizes(digest, now) && satisfies(approved, ev) {
		return nil, scangov.ErrNotRequired
	}
	if lack := ev.CheckEvidence(in.Justification, in.Ticket); lack != "" {
		return nil, shared.NewDomainError("SCAN_APPROVAL_EVIDENCE", "The approval rule needs more: "+lack+".", shared.ErrValidation)
	}
	req := scangov.NewRequest(tenantID, scanID, def, ev, actor.UserID, in.Justification, in.Ticket, in.RunOnApproval, st.PendingDays(), now)
	if last, err := s.repo.LastApproved(ctx, tenantID, scanID); err != nil {
		return nil, err
	} else if last != nil {
		req.Changes = scangov.Diff(last.Definition, def)
	}
	if err := s.repo.SupersedePending(ctx, tenantID, scanID, "", now); err != nil {
		return nil, err
	}
	if err := s.repo.Create(ctx, req); err != nil {
		return nil, err
	}
	req.ScanName = sc.Name
	s.logAudit(ctx, actor.AuditContext, tenantID, auditapp.NewSuccessEvent(audit.ActionScanApprovalRequested, audit.ResourceTypeScanConfig, scanID.String()).
		WithResourceName(sc.Name).
		WithMessage("Scan submitted for approval").
		WithMetadata("request_id", req.ID.String()).
		WithMetadata("rules", ruleNames(ev.Matched)).
		WithMetadata("approvals", ev.Approvals).
		WithMetadata("changed_fields", len(req.Changes)))
	s.notifyApprovers(ctx, req, sc.Name, "Scan waiting for your approval")
	return req, nil
}

func ruleNames(rs []scangov.MatchedRule) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Name)
	}
	return out
}

// loadPending loads a tenant's request for a decision.
func (s *Service) load(ctx context.Context, tenantID, id shared.ID) (*scangov.Request, error) {
	if err := s.requireRepo(); err != nil {
		return nil, err
	}
	req, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if req.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return req, nil
}

// directory returns the organization's approvers (an error refuses).
func (s *Service) directory(ctx context.Context, tenantID shared.ID) ([]scangov.Approver, error) {
	if s.approvers == nil {
		return nil, nil
	}
	all, err := s.approvers.ScanApprovers(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list scan approvers: %w", err)
	}
	return all, nil
}

func approverOf(all []scangov.Approver, userID string) (scangov.Approver, bool) {
	i := slices.IndexFunc(all, func(a scangov.Approver) bool { return a.UserID == userID })
	if i < 0 {
		return scangov.Approver{}, false
	}
	return all[i], true
}

// save writes a decided request; a concurrent decision wins (conflict).
func (s *Service) save(ctx context.Context, req *scangov.Request) error {
	ok, err := s.repo.Update(ctx, req, scangov.StatusPending)
	if err != nil {
		return err
	}
	if !ok {
		return scangov.ErrNotPending
	}
	return nil
}

// Approve records the actor's approval. The actor must be one of the
// organization's approvers the rule allows, never the requester.
func (s *Service) Approve(ctx context.Context, tenantID, id shared.ID, note string, actor Actor) (*scangov.Request, error) {
	if len(note) > scangov.MaxNoteLen {
		return nil, fmt.Errorf("%w: note: at most %d characters", shared.ErrValidation, scangov.MaxNoteLen)
	}
	req, err := s.load(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	all, err := s.directory(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if actor.UserID == req.RequestedBy {
		return nil, scangov.ErrOwnRequest
	}
	a, ok := approverOf(all, actor.UserID)
	if !ok || !req.EligibleFor(a) {
		return nil, scangov.ErrNotEligible
	}
	if err := req.Approve(actor.UserID, note, s.clock()); err != nil {
		return nil, err
	}
	if err := s.save(ctx, req); err != nil {
		return nil, err
	}
	s.logAudit(ctx, actor.AuditContext, tenantID, auditapp.NewSuccessEvent(audit.ActionScanApprovalApproved, audit.ResourceTypeScanConfig, req.ScanID.String()).
		WithResourceName(req.ScanName).
		WithMessage("Scan approval given").
		WithMetadata("request_id", req.ID.String()).
		WithMetadata("remaining", req.Remaining()))
	s.afterDecision(ctx, req, actor)
	return req, nil
}

// SelfApprove is an owner's approval of their own request when no other
// approver can give the remaining approvals, with a fresh authenticator
// code and a reason.
func (s *Service) SelfApprove(ctx context.Context, tenantID, id shared.ID, reason, code string, actor Actor) (*scangov.Request, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > scangov.MaxNoteLen {
		return nil, fmt.Errorf("%w: a reason (at most %d characters) is required", shared.ErrValidation, scangov.MaxNoteLen)
	}
	req, err := s.load(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	all, err := s.directory(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if !req.SelfApprovalAllowed(actor.UserID, all, s.clock()) {
		return nil, scangov.ErrSelfNotAllowed
	}
	if s.totp == nil {
		return nil, scangov.ErrSelfNotAllowed
	}
	if err := s.totp.VerifyFreshTOTP(ctx, actor.UserID, strings.TrimSpace(code)); err != nil {
		return nil, err
	}
	if err := req.SelfApprove(actor.UserID, reason, s.clock()); err != nil {
		return nil, err
	}
	if err := s.save(ctx, req); err != nil {
		return nil, err
	}
	s.logAudit(ctx, actor.AuditContext, tenantID, auditapp.NewSuccessEvent(audit.ActionScanApprovalSelfApprov, audit.ResourceTypeScanConfig, req.ScanID.String()).
		WithResourceName(req.ScanName).
		WithSeverity(audit.SeverityHigh).
		WithMessage("Scan approved by its own requester: no other approver exists").
		WithMetadata("request_id", req.ID.String()).
		WithMetadata("reason", reason).
		WithMetadata("second_factor", "totp"))
	s.notifyAdmins(ctx, tenantID, all, actor.UserID, "Scan approved by its requester",
		fmt.Sprintf("%q was approved by its requester, the organization's owner, with an authenticator code: no other approver exists. Reason: %s", req.ScanName, oneLine(reason, 300)), req.ScanID)
	s.afterDecision(ctx, req, actor)
	return req, nil
}

// afterDecision announces an approval that completed and starts the run the
// requester asked for.
func (s *Service) afterDecision(ctx context.Context, req *scangov.Request, actor Actor) {
	if req.Status != scangov.StatusApproved {
		return
	}
	s.logAudit(ctx, actor.AuditContext, req.TenantID, auditapp.NewSuccessEvent(audit.ActionScanApprovalGranted, audit.ResourceTypeScanConfig, req.ScanID.String()).
		WithResourceName(req.ScanName).
		WithMessage("Scan definition approved").
		WithMetadata("request_id", req.ID.String()).
		WithMetadata("validity", string(req.Evaluation.Validity)))
	s.notifyUser(ctx, req.TenantID, req.RequestedBy, "Scan approved", fmt.Sprintf("%q was approved.", req.ScanName), "info", req.ScanID)
	if !req.RunOnApproval || s.scans == nil {
		return
	}
	// The run starts as the requester and passes every gate again (act
	// scope, scope, tier, proof, zones, windows, this approval).
	if err := s.scans.RunApproved(context.WithoutCancel(ctx), req.TenantID, req.ScanID, req.RequestedBy); err != nil {
		s.log.Warn("run after approval refused", "scan_id", req.ScanID.String(), "error", logger.SanitizeError(err))
	}
}

// Reject closes a pending request.
func (s *Service) Reject(ctx context.Context, tenantID, id shared.ID, note string, actor Actor) (*scangov.Request, error) {
	if len(note) > scangov.MaxNoteLen {
		return nil, fmt.Errorf("%w: note: at most %d characters", shared.ErrValidation, scangov.MaxNoteLen)
	}
	req, err := s.load(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	all, err := s.directory(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if actor.UserID == req.RequestedBy {
		return nil, scangov.ErrOwnRequest
	}
	if a, ok := approverOf(all, actor.UserID); !ok || !req.EligibleFor(a) {
		return nil, scangov.ErrNotEligible
	}
	if err := req.Reject(actor.UserID, note, s.clock()); err != nil {
		return nil, err
	}
	if err := s.save(ctx, req); err != nil {
		return nil, err
	}
	s.logAudit(ctx, actor.AuditContext, tenantID, auditapp.NewSuccessEvent(audit.ActionScanApprovalRejected, audit.ResourceTypeScanConfig, req.ScanID.String()).
		WithResourceName(req.ScanName).
		WithMessage("Scan approval rejected").
		WithMetadata("request_id", req.ID.String()).
		WithMetadata("note", oneLine(note, 300)))
	s.notifyUser(ctx, tenantID, req.RequestedBy, "Scan approval rejected", fmt.Sprintf("%q was rejected: %s", req.ScanName, oneLine(note, 300)), "medium", req.ScanID)
	return req, nil
}

// Cancel withdraws the requester's own pending request.
func (s *Service) Cancel(ctx context.Context, tenantID, id shared.ID, actor Actor) (*scangov.Request, error) {
	req, err := s.load(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if err := req.Cancel(actor.UserID, s.clock()); err != nil {
		return nil, err
	}
	if err := s.save(ctx, req); err != nil {
		return nil, err
	}
	s.logAudit(ctx, actor.AuditContext, tenantID, auditapp.NewSuccessEvent(audit.ActionScanApprovalCanceled, audit.ResourceTypeScanConfig, req.ScanID.String()).
		WithResourceName(req.ScanName).
		WithMessage("Scan approval request withdrawn").
		WithMetadata("request_id", req.ID.String()))
	return req, nil
}

// Remind sends the request again to the approvers who can still approve
// it, at most once an hour (checked atomically).
func (s *Service) Remind(ctx context.Context, tenantID, id shared.ID, actor Actor) (*scangov.Request, int, error) {
	req, err := s.load(ctx, tenantID, id)
	if err != nil {
		return nil, 0, err
	}
	now := s.clock()
	if !req.IsPending(now) {
		return nil, 0, scangov.ErrNotPending
	}
	ok, err := s.repo.MarkReminded(ctx, tenantID, id, now, scangov.ReminderInterval)
	if err != nil {
		return nil, 0, err
	}
	if !ok {
		return nil, 0, scangov.ErrReminderTooSoon
	}
	at := now.UTC()
	req.RemindedAt = &at
	n := s.notifyApprovers(ctx, req, req.ScanName, "Reminder: scan waiting for your approval")
	s.logAudit(ctx, actor.AuditContext, tenantID, auditapp.NewSuccessEvent(audit.ActionScanApprovalReminded, audit.ResourceTypeScanConfig, req.ScanID.String()).
		WithResourceName(req.ScanName).
		WithMessage("Approvers of a scan reminded").
		WithMetadata("request_id", req.ID.String()).
		WithMetadata("reminded", n))
	return req, n, nil
}

// EmergencyInput is an emergency run.
type EmergencyInput struct {
	Reason string
	Hours  int
}

// Emergency lets an owner or administrator run a scan that needs an
// approval it does not have, now and for a few hours (1-24, default 4),
// with a reason (the route checked step-up). Audited critical; every
// administrator is told. The run passes every other gate.
func (s *Service) Emergency(ctx context.Context, tenantID, scanID shared.ID, in EmergencyInput, actor Actor) (*scangov.Request, error) {
	if err := s.requireRepo(); err != nil {
		return nil, err
	}
	reason := strings.TrimSpace(in.Reason)
	if reason == "" || len(reason) > scangov.MaxNoteLen {
		return nil, fmt.Errorf("%w: a reason (at most %d characters) is required", shared.ErrValidation, scangov.MaxNoteLen)
	}
	if in.Hours < 0 || in.Hours > scangov.MaxEmergencyHours {
		return nil, fmt.Errorf("%w: hours must be 1 to %d", shared.ErrValidation, scangov.MaxEmergencyHours)
	}
	all, err := s.directory(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if a, ok := approverOf(all, actor.UserID); !ok || (a.Role != scangov.RoleOwner && a.Role != scangov.RoleAdmin) {
		return nil, scangov.ErrEmergencyNotAdmin
	}
	if s.scans == nil {
		return nil, fmt.Errorf("%w: scans not wired", shared.ErrInternal)
	}
	sc, def, facts, err := s.scans.GovernanceSubject(ctx, tenantID, scanID)
	if err != nil {
		return nil, err
	}
	m, st, err := s.rules(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if m == scangov.ModeOff {
		return nil, scangov.ErrGovernanceOff
	}
	if facts, err = s.withRequester(ctx, tenantID, st.Rules, facts, actor.UserID, s.clock()); err != nil {
		return nil, err
	}
	ev := scangov.Evaluate(m, st.Rules, facts)
	if !ev.Required {
		return nil, scangov.ErrNotRequired
	}
	req := scangov.NewEmergency(tenantID, scanID, def, ev, actor.UserID, reason, in.Hours, s.clock())
	if err := s.repo.Create(ctx, req); err != nil {
		return nil, err
	}
	req.ScanName = sc.Name
	s.logAudit(ctx, actor.AuditContext, tenantID, auditapp.NewSuccessEvent(audit.ActionScanEmergencyRun, audit.ResourceTypeScanConfig, scanID.String()).
		WithResourceName(sc.Name).
		WithSeverity(audit.SeverityCritical).
		WithMessage("Emergency run of a scan without its approval").
		WithMetadata("request_id", req.ID.String()).
		WithMetadata("reason", reason).
		WithMetadata("valid_until", req.ValidUntil.Format("2006-01-02T15:04:05Z07:00")).
		WithMetadata("rules", ruleNames(ev.Matched)))
	s.notifyAdmins(ctx, tenantID, all, actor.UserID, "Emergency scan run",
		fmt.Sprintf("%q was run without its approval, as an emergency, until %s. Reason: %s", sc.Name, req.ValidUntil.Format("2006-01-02 15:04 MST"), oneLine(reason, 300)), scanID)
	if err := s.scans.RunApproved(ctx, tenantID, scanID, actor.UserID); err != nil {
		return req, err
	}
	return req, nil
}

// List returns a tenant's requests (overdue pending requests are expired
// first).
func (s *Service) List(ctx context.Context, f scangov.ListFilter) ([]*scangov.Request, int, error) {
	if err := s.requireRepo(); err != nil {
		return nil, 0, err
	}
	if _, err := s.repo.ExpireOverdue(ctx, f.TenantID, s.clock()); err != nil {
		s.log.Warn("expire scan approval requests", "error", logger.SanitizeError(err))
	}
	if f.Limit <= 0 || f.Limit > 100 {
		f.Limit = 50
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	return s.repo.List(ctx, f)
}

// Get returns one of the tenant's requests.
func (s *Service) Get(ctx context.Context, tenantID, id shared.ID) (*scangov.Request, error) {
	return s.load(ctx, tenantID, id)
}

// Approvers answers who may still approve req, and whether viewer may
// approve it themselves.
func (s *Service) Approvers(ctx context.Context, req *scangov.Request, viewer string) ([]scangov.Approver, bool, error) {
	all, err := s.directory(ctx, req.TenantID)
	if err != nil {
		return nil, false, err
	}
	return req.Eligible(all), req.SelfApprovalAllowed(viewer, all, s.clock()), nil
}

// LatestByScans returns the newest request of each scan (list badges).
func (s *Service) LatestByScans(ctx context.Context, tenantID shared.ID, scans []*scan.Scan) (map[shared.ID]*scangov.Request, error) {
	ids := make([]shared.ID, 0, len(scans))
	for _, sc := range scans {
		if sc != nil && sc.TenantID == tenantID {
			ids = append(ids, sc.ID)
		}
	}
	if len(ids) == 0 || s.repo == nil {
		return map[shared.ID]*scangov.Request{}, nil
	}
	return s.repo.LatestByScans(ctx, tenantID, ids)
}

func (s *Service) notifyApprovers(ctx context.Context, req *scangov.Request, scanName, title string) int {
	all, err := s.directory(ctx, req.TenantID)
	if err != nil {
		s.log.Warn("scan approvers: list", "error", logger.SanitizeError(err))
		return 0
	}
	body := fmt.Sprintf("%q (%s, %d target(s)) needs %d approval(s): %s.", scanName, req.Definition.Intensity,
		len(req.Definition.Targets)+len(req.Definition.AssetGroupIDs), req.Remaining(), strings.Join(ruleNames(req.Evaluation.Matched), "; "))
	eligible := req.Eligible(all)
	for _, a := range eligible {
		s.notifyUser(ctx, req.TenantID, a.UserID, title, body, "high", req.ScanID)
	}
	return len(eligible)
}

func (s *Service) notifyAdmins(ctx context.Context, tenantID shared.ID, all []scangov.Approver, except, title, body string, scanID shared.ID) {
	for _, a := range all {
		if a.UserID != except && (a.Role == scangov.RoleOwner || a.Role == scangov.RoleAdmin) {
			s.notifyUser(ctx, tenantID, a.UserID, title, body, "high", scanID)
		}
	}
}

// IsGovernanceError reports whether err is one of the coded governance
// refusals (the handler answers them with their code).
func IsGovernanceError(err error) bool {
	var de *shared.DomainError
	return errors.As(err, &de) && strings.HasPrefix(de.Code, "SCAN_APPROVAL")
}
