package scope

// Who approves a pending scope entry, reminders, and an owner's own approval
// when nobody else can (RFC-054 §7, amendment 2026-10-09).
//
// Threat model: the second approval protects against a typo and against a
// single stolen session widening scope. Naming the approvers and reminding
// them changes nobody's power. The one relaxation, an owner approving their
// own entry, is allowed only when no other member can approve it, needs a
// fresh code from the owner's authenticator app (a stolen cookie or password
// alone is not enough) and a reason, is audited at high severity and is
// announced to every administrator and on the organization's channels.
// Nothing is ever approved automatically.

import (
	"context"
	"fmt"
	"html"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ApproverDirectory lists the organization's scope approvers
// (*postgres.ScopeActorRepository).
type ApproverDirectory interface {
	ScopeApprovers(ctx context.Context, tenantID shared.ID) ([]scopedom.Approver, error)
}

// TOTPVerifier checks a fresh code from the user's authenticator app. It
// answers scopedom.ErrSelfApprovalNeedsTOTP when the account has no
// authenticator and scopedom.ErrSelfApprovalBadCode for a wrong or reused
// code; a used code cannot be used again.
type TOTPVerifier interface {
	VerifyFreshTOTP(ctx context.Context, userID, code string) error
}

// ApprovalMailer emails approval requests (best effort, asynchronous).
type ApprovalMailer interface {
	SendScopeApprovalMail(ctx context.Context, tenantID string, to []string, subject, htmlBody string)
}

// ChannelNotifier enqueues an event for the organization's notification
// channels (*outbox.Service).
type ChannelNotifier interface {
	Enqueue(ctx context.Context, params outbox.EnqueueParams) error
}

// reminderStore records reminders atomically
// (*postgres.ScopeTargetRepository).
type reminderStore interface {
	MarkReminded(ctx context.Context, tenantID, id shared.ID, now time.Time, minInterval time.Duration) (bool, error)
}

// SetApprovers wires the approver directory, the authenticator check for an
// owner's own approval, the approval emails and the channels. Without a
// directory no approver is named and self-approval is refused; without a
// verifier self-approval is refused (fail closed).
func (s *Service) SetApprovers(dir ApproverDirectory, totp TOTPVerifier, mail ApprovalMailer, channels ChannelNotifier, webBaseURL string) {
	s.approvers, s.totp, s.mail, s.channels = dir, totp, mail, channels
	s.webBaseURL = strings.TrimRight(webBaseURL, "/")
}

// ApprovalStatus is who can still approve a pending entry.
type ApprovalStatus struct {
	// Remaining approvals the entry needs.
	Remaining int
	// Eligible approvers: everyone who may approve scope entries except the
	// requester and those who already approved.
	Eligible []scopedom.Approver
	// SelfApprovalAvailable: the viewer may approve their own entry (they
	// requested it, are an owner, hold the approval permission, and the
	// eligible approvers cannot give the remaining approvals).
	SelfApprovalAvailable bool
}

// ApprovalStatuses answers the approval status of the pending entries among
// targets, keyed by entry id, as seen by viewer. One directory read for the
// whole list. A tenant mismatch is skipped (the list is tenant-scoped
// already).
func (s *Service) ApprovalStatuses(ctx context.Context, tenantID shared.ID, targets []*scopedom.Target, viewer Actor) (map[string]ApprovalStatus, error) {
	out := map[string]ApprovalStatus{}
	pending := make([]*scopedom.Target, 0, len(targets))
	for _, t := range targets {
		if t != nil && t.IsPending() && t.TenantID() == tenantID {
			pending = append(pending, t)
		}
	}
	if len(pending) == 0 || s.approvers == nil {
		return out, nil
	}
	all, err := s.approvers.ScopeApprovers(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list scope approvers: %w", err)
	}
	for _, t := range pending {
		out[t.ID().String()] = approvalStatus(t, all, viewer)
	}
	return out, nil
}

func approvalStatus(t *scopedom.Target, all []scopedom.Approver, viewer Actor) ApprovalStatus {
	st := ApprovalStatus{Remaining: t.RemainingApprovals(), Eligible: scopedom.EligibleApprovers(t, all)}
	st.SelfApprovalAvailable = selfApprovalAllowed(t, all, st, viewer)
	return st
}

// selfApprovalAllowed is the rule for an owner's own approval: the viewer
// requested the entry, holds the approval permission, is an owner of the
// organization (read from the membership, not the token), and the other
// approvers cannot give the remaining approvals.
func selfApprovalAllowed(t *scopedom.Target, all []scopedom.Approver, st ApprovalStatus, viewer Actor) bool {
	if viewer.system() || !viewer.CanApprove || viewer.UserID != t.CreatedBy() || st.Remaining == 0 {
		return false
	}
	owner := slices.ContainsFunc(all, func(a scopedom.Approver) bool { return a.UserID == viewer.UserID && a.Owner })
	return owner && len(st.Eligible) < st.Remaining
}

// SelfApproveTarget puts the actor's own pending entry into effect when no
// other approver can (see selfApprovalAllowed). The actor proves presence
// with a fresh authenticator code and gives a reason. The route requires
// attack_surface:scope:approve; the handler audits at high severity.
func (s *Service) SelfApproveTarget(ctx context.Context, targetID, tenantID string, actor Actor, reason, code string) (*scopedom.Target, error) {
	t, err := s.GetTarget(ctx, tenantID, targetID)
	if err != nil {
		return nil, err
	}
	if actor.system() || !actor.CanApprove {
		return nil, ErrWideningNeedsApprove
	}
	now := time.Now().UTC()
	switch {
	case t.Status() == scopedom.StatusRejected:
		return nil, scopedom.ErrEntryRejected
	case !t.IsPending():
		return nil, scopedom.ErrEntryNotPending
	case t.ExpiredAt(now):
		return nil, scopedom.ErrEntryExpired
	}
	if s.approvers == nil {
		return nil, scopedom.ErrSelfApprovalNotAllowed
	}
	all, err := s.approvers.ScopeApprovers(ctx, t.TenantID())
	if err != nil {
		return nil, fmt.Errorf("list scope approvers: %w", err)
	}
	if !approvalStatus(t, all, actor).SelfApprovalAvailable {
		return nil, scopedom.ErrSelfApprovalNotAllowed
	}
	if strings.TrimSpace(reason) == "" {
		return nil, scopedom.ErrSelfApprovalNeedsReason
	}
	if s.totp == nil {
		return nil, ErrStepUpNotWired
	}
	if strings.TrimSpace(code) == "" {
		return nil, scopedom.ErrSelfApprovalBadCode
	}
	if err := s.totp.VerifyFreshTOTP(ctx, actor.UserID, code); err != nil {
		return nil, err
	}
	if err := t.SelfApprove(actor.UserID, reason, now); err != nil {
		return nil, err
	}
	if err := s.targetRepo.Update(ctx, t); err != nil {
		return nil, fmt.Errorf("failed to approve scope target: %w", err)
	}
	title := "Scope entry approved by its own requester (no other approver)"
	body := fmt.Sprintf("%s %s (%s, max tier %s) was approved by the owner who requested it, because no other approver exists. Reason: %s",
		t.TargetType(), t.Pattern(), describeExpiry(t), t.MaxTier(), strings.TrimSpace(reason))
	s.NotifyAdmins(ctx, t.TenantID(), title, body)
	s.enqueueChannel(ctx, t, string(integration.EventTypeSecurityAlert), title, body, notificationdom.SeverityHigh)
	s.scheduleJoin(t.TenantID())
	s.logger.Warn("scope target self-approved", "id", logSafe(targetID))
	return t, nil
}

// RemindApprovers reminds the eligible approvers of a pending entry, at most
// once per scopedom.ReminderInterval per entry (checked atomically). It
// answers how many approvers were reminded. The route requires
// attack_surface:scope:write.
func (s *Service) RemindApprovers(ctx context.Context, targetID, tenantID string, actor Actor) (*scopedom.Target, int, error) {
	t, err := s.GetTarget(ctx, tenantID, targetID)
	if err != nil {
		return nil, 0, err
	}
	if actor.system() {
		return nil, 0, fmt.Errorf("%w: a reminder needs a person", shared.ErrValidation)
	}
	now := time.Now().UTC()
	if !t.IsPending() {
		return nil, 0, scopedom.ErrEntryNotPending
	}
	if t.ExpiredAt(now) {
		return nil, 0, scopedom.ErrEntryExpired
	}
	store, ok := s.targetRepo.(reminderStore)
	if !ok {
		return nil, 0, fmt.Errorf("%w: reminders are not available", shared.ErrNotImplemented)
	}
	marked, err := store.MarkReminded(ctx, t.TenantID(), t.ID(), now, scopedom.ReminderInterval)
	if err != nil {
		return nil, 0, err
	}
	if !marked {
		return nil, 0, scopedom.ErrReminderTooSoon
	}
	t.RestoreRemindedAt(&now)
	n := s.notifyApprovers(ctx, t, "Reminder: scope entry awaiting your approval", true)
	return t, n, nil
}

// notifyRequested tells the approvers and the administrators that an entry
// waits for approval: in-app for every administrator and every eligible
// approver, an email to each eligible approver, and the approval_requested
// event on the organization's channels.
func (s *Service) notifyRequested(ctx context.Context, t *scopedom.Target) {
	s.NotifyAdmins(ctx, t.TenantID(), "Scope entry awaiting approval", requestBody(t))
	s.notifyApprovers(ctx, t, "Scope entry awaiting your approval", false)
}

func requestBody(t *scopedom.Target) string {
	return fmt.Sprintf("%s %s (%s, max tier %s) needs %d more approval(s). Reason: %s",
		t.TargetType(), t.Pattern(), describeExpiry(t), t.MaxTier(), t.RemainingApprovals(), t.Reason())
}

// notifyApprovers delivers an approval request to the eligible approvers
// (in-app and email; the administrators among them were told by
// NotifyAdmins on the first request, so only a reminder repeats in-app for
// them) and to the channels. It answers how many approvers it reached.
// Best effort: the entry is saved and audited already.
func (s *Service) notifyApprovers(ctx context.Context, t *scopedom.Target, title string, reminder bool) int {
	body := requestBody(t)
	s.enqueueChannel(ctx, t, string(integration.EventTypeApprovalRequested), title, body, notificationdom.SeverityMedium)
	if s.approvers == nil {
		return 0
	}
	all, err := s.approvers.ScopeApprovers(ctx, t.TenantID())
	if err != nil {
		s.logger.Warn("scope approvers: list", "error", logger.SanitizeError(err))
		return 0
	}
	eligible := scopedom.EligibleApprovers(t, all)
	admins := map[string]bool{}
	if !reminder && s.admins != nil {
		if ids, err := s.admins.ActiveAdminIDs(ctx, t.TenantID()); err == nil {
			for _, id := range ids {
				admins[id.String()] = true
			}
		}
	}
	emails := make([]string, 0, len(eligible))
	for _, a := range eligible {
		if a.Email != "" {
			emails = append(emails, a.Email)
		}
		if admins[a.UserID] || s.inApp == nil {
			continue
		}
		uid, err := shared.IDFromString(a.UserID)
		if err != nil {
			continue
		}
		if err := s.inApp.Notify(ctx, notificationdom.NotificationParams{
			TenantID: t.TenantID(), Audience: notificationdom.AudienceUser, AudienceID: &uid,
			NotificationType: notificationdom.TypeScopeChange, Title: title, Body: body, Severity: "high",
			ResourceType: "scope", URL: "/scope",
		}); err != nil {
			s.logger.Warn("scope approvers: in-app notification", "error", logger.SanitizeError(err))
		}
	}
	if s.mail != nil && len(emails) > 0 {
		s.mail.SendScopeApprovalMail(ctx, t.TenantID().String(), emails, "[Scope] "+title+": "+t.Pattern(), s.approvalMailBody(t))
	}
	return len(eligible)
}

// approvalMailBody is the approval request email. Every value from the
// organization is escaped; the link only opens the page (sign-in and the
// approval permission authorize), so a forwarded email grants nothing.
func (s *Service) approvalMailBody(t *scopedom.Target) string {
	link := s.webBaseURL + "/scope"
	return fmt.Sprintf(`<p>A scope entry is waiting for your approval.</p>
<p><strong>%s</strong> (%s), %s, deepest probe %s.</p>
<p>Reason: %s</p>
<p>It authorizes nothing until it has %d more approval(s). Review it: <a href="%s">%s</a> (sign-in required).</p>`,
		html.EscapeString(t.Pattern()), html.EscapeString(t.TargetType().String()), html.EscapeString(describeExpiry(t)),
		html.EscapeString(t.MaxTier().String()), html.EscapeString(t.Reason()), t.RemainingApprovals(),
		html.EscapeString(link), html.EscapeString(link))
}

// enqueueChannel puts a scope event on the organization's notification
// channels (best effort).
func (s *Service) enqueueChannel(ctx context.Context, t *scopedom.Target, eventType, title, body, severity string) {
	if s.channels == nil {
		return
	}
	var agg *uuid.UUID
	if id, err := uuid.Parse(t.ID().String()); err == nil {
		agg = &id
	}
	if err := s.channels.Enqueue(ctx, outbox.EnqueueParams{
		TenantID: t.TenantID(), EventType: eventType, AggregateType: "scope_target", AggregateID: agg,
		Title: title, Body: body, Severity: severity, URL: "/scope",
	}); err != nil {
		s.logger.Warn("scope notice: enqueue", "event_type", eventType, "error", logger.SanitizeError(err))
	}
}
