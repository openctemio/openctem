package finding

// Who is told that a finding false-positive or accepted-risk request waits
// for a decision, and reminders (api/docs/architecture/finding-status-lifecycle.md,
// "Approvals").
//
// Threat model: telling approvers changes nobody's power; the second person
// still decides in the app, signed in, with the approve permission and the
// finding in their data scope. What a notification may leak is bounded: only
// members who could approve the request AND see the finding are told (never
// the requester, never a member outside the finding's data scope), and the
// email carries the finding title, the requested status and the dates, never
// the justification (untrusted free text) or evidence. The link only opens
// the inbox; a forwarded email grants nothing.

import (
	"context"
	"errors"
	"fmt"
	"html"
	"strings"
	"time"

	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// FindingApprover is a member who may approve finding status requests
// (owner, admin, or a role carrying findings:approve), with an active account
// and membership.
type FindingApprover struct {
	UserID string
	Name   string
	Email  string
	Owner  bool
}

// FindingApproverDirectory lists the organization's finding approvers
// (*postgres.ScopeActorRepository).
type FindingApproverDirectory interface {
	FindingApprovers(ctx context.Context, tenantID shared.ID) ([]FindingApprover, error)
}

// ApprovalInApp delivers in-app notifications
// (*integration.NotificationService).
type ApprovalInApp interface {
	Notify(ctx context.Context, params notificationdom.NotificationParams) error
}

// FindingApprovalMailer emails approval requests (best effort, asynchronous).
type FindingApprovalMailer interface {
	SendFindingApprovalMail(ctx context.Context, tenantID string, to []string, subject, htmlBody string)
}

// approvalReminderStore records reminders atomically
// (*postgres.FindingApprovalRepository).
type approvalReminderStore interface {
	MarkReminded(ctx context.Context, tenantID, id shared.ID, now time.Time, minInterval time.Duration) (bool, error)
}

// approvalInboxURL is the approvals inbox in the web console.
const approvalInboxURL = "/findings/approvals"

// SetApprovalNotifier wires who is told about a pending request: the
// approver directory, in-app notifications and email. Any of them may be nil
// (that channel is skipped); without a directory nobody is told.
func (s *VulnerabilityService) SetApprovalNotifier(dir FindingApproverDirectory, inApp ApprovalInApp, mail FindingApprovalMailer, webBaseURL string) {
	s.approverDir, s.approvalInApp, s.approvalMail = dir, inApp, mail
	s.webBaseURL = strings.TrimRight(webBaseURL, "/")
}

// eligibleApprovers are the members who may decide the request: they hold
// the approve permission, are not its requester, and the finding is in their
// data scope.
func (s *VulnerabilityService) eligibleApprovers(ctx context.Context, a *vulnerability.Approval) ([]FindingApprover, error) {
	if s.approverDir == nil {
		return nil, nil
	}
	all, err := s.approverDir.FindingApprovers(ctx, a.TenantID)
	if err != nil {
		return nil, fmt.Errorf("list finding approvers: %w", err)
	}
	// The owners of the finding's asset never approve its decisions
	// (approval policy): they are not asked either.
	owners := map[shared.ID]bool{}
	if r, ok := s.approvalRepo.(policyFactsReader); ok {
		if pf, err := r.PolicyFacts(ctx, a.TenantID, a.FindingID); err == nil {
			for _, id := range pf.AssetOwners {
				owners[id] = true
			}
		}
	}
	out := make([]FindingApprover, 0, len(all))
	for _, ap := range all {
		uid, err := shared.IDFromString(ap.UserID)
		if err != nil || (!a.RequestedBy.IsZero() && uid == a.RequestedBy) || owners[uid] {
			continue
		}
		if s.dataScope != nil {
			if err := s.dataScope.AssertFindingForUser(ctx, a.TenantID, uid, a.FindingID); err != nil {
				if !errors.Is(err, shared.ErrNotFound) {
					s.logger.Warn("finding approvers: data scope", "error", logger.SanitizeError(err))
				}
				continue
			}
		}
		out = append(out, ap)
	}
	return out, nil
}

// notifyApprovers tells the eligible approvers that a request waits for
// them: in-app and by email. Best effort (the request is saved already); it
// answers how many approvers it reached.
func (s *VulnerabilityService) notifyApprovers(ctx context.Context, a *vulnerability.Approval, findingTitle string, reminder bool) int {
	eligible, err := s.eligibleApprovers(ctx, a)
	if err != nil {
		s.logger.Warn("finding approvers: list", "error", logger.SanitizeError(err))
		return 0
	}
	if len(eligible) == 0 {
		return 0
	}
	title := "Finding approval requested: " + statusLabel(a.RequestedStatus)
	if reminder {
		title = "Reminder: " + title
	}
	body := approvalSummary(a, findingTitle)
	emails := make([]string, 0, len(eligible))
	for _, ap := range eligible {
		if ap.Email != "" {
			emails = append(emails, ap.Email)
		}
		if s.approvalInApp == nil {
			continue
		}
		uid, err := shared.IDFromString(ap.UserID)
		if err != nil {
			continue
		}
		fid := a.FindingID
		if err := s.approvalInApp.Notify(ctx, notificationdom.NotificationParams{
			TenantID: a.TenantID, Audience: notificationdom.AudienceUser, AudienceID: &uid,
			NotificationType: notificationdom.TypeFindingApproval, Title: title, Body: body,
			Severity: notificationdom.SeverityMedium, ResourceType: "finding", ResourceID: &fid, URL: approvalInboxURL,
		}); err != nil {
			s.logger.Warn("finding approvers: in-app notification", "error", logger.SanitizeError(err))
		}
	}
	if s.approvalMail != nil && len(emails) > 0 {
		s.approvalMail.SendFindingApprovalMail(ctx, a.TenantID.String(), emails, "[Findings] "+title, s.approvalMailBody(a, findingTitle))
	}
	return len(eligible)
}

// RemindApprovers reminds the eligible approvers of a pending request, at
// most once per vulnerability.ApprovalReminderInterval per request (checked
// atomically in the database). The route requires findings:write; the
// request's finding must be in the caller's data scope. It answers the
// request and how many approvers were reminded.
func (s *VulnerabilityService) RemindApprovers(ctx context.Context, tenantID, approvalID string) (*vulnerability.Approval, int, error) {
	if s.approvalRepo == nil {
		return nil, 0, fmt.Errorf("%w: approval workflow not configured", shared.ErrValidation)
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	aid, err := shared.IDFromString(approvalID)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: invalid approval id", shared.ErrValidation)
	}
	a, err := s.approvalRepo.GetByTenantAndID(ctx, tid, aid)
	if err != nil {
		return nil, 0, err
	}
	if a.BatchID != nil {
		return nil, 0, vulnerability.ErrBatchMember
	}
	if err := s.dataScope.AssertFinding(ctx, tid, a.FindingID); err != nil {
		return nil, 0, err
	}
	now := time.Now()
	if !a.IsPending() {
		return nil, 0, fmt.Errorf("%w: approval is not pending", shared.ErrValidation)
	}
	if a.IsOverdue(now) {
		return nil, 0, vulnerability.ErrDecisionOverdue
	}
	store, ok := s.approvalRepo.(approvalReminderStore)
	if !ok {
		return nil, 0, fmt.Errorf("%w: reminders are not available", shared.ErrNotImplemented)
	}
	marked, err := store.MarkReminded(ctx, tid, aid, now, vulnerability.ApprovalReminderInterval)
	if err != nil {
		return nil, 0, err
	}
	if !marked {
		return nil, 0, vulnerability.ErrApprovalReminderTooSoon
	}
	return a, s.notifyApprovers(ctx, a, s.findingTitle(ctx, a), true), nil
}

// findingTitle is the title of the request's finding ("" when it cannot be
// read; the notification still goes out).
func (s *VulnerabilityService) findingTitle(ctx context.Context, a *vulnerability.Approval) string {
	f, err := s.findingRepo.GetByID(ctx, a.TenantID, a.FindingID)
	if err != nil {
		return ""
	}
	return f.Title()
}

func statusLabel(status string) string {
	switch vulnerability.FindingStatus(status) {
	case vulnerability.FindingStatusFalsePositive:
		return "false positive"
	case vulnerability.FindingStatusAccepted:
		return "accepted risk"
	}
	return status
}

// approvalSummary is the plain-text body of an in-app notification: the
// finding, the requested status and the dates; no justification.
func approvalSummary(a *vulnerability.Approval, findingTitle string) string {
	var b strings.Builder
	if t := oneLineTitle(findingTitle); t != "" {
		b.WriteString(t)
		b.WriteString(": ")
	}
	b.WriteString(statusLabel(a.RequestedStatus))
	if a.ExpiresAt != nil {
		b.WriteString(", until ")
		b.WriteString(a.ExpiresAt.UTC().Format("2006-01-02"))
	}
	if a.DecideBy != nil {
		b.WriteString(". Decide by ")
		b.WriteString(a.DecideBy.UTC().Format("2006-01-02"))
	}
	b.WriteString(".")
	return b.String()
}

// approvalMailBody is the email of a request. Every value from the
// organization is escaped; the link only opens the inbox (sign-in, the
// approve permission and the data scope authorize).
func (s *VulnerabilityService) approvalMailBody(a *vulnerability.Approval, findingTitle string) string {
	link := s.webBaseURL + approvalInboxURL
	return fmt.Sprintf(`<p>A finding request is waiting for your decision.</p>
<p>%s</p>
<p>Another person must approve or reject it; the requester cannot. Review it: <a href="%s">%s</a> (sign-in required).</p>`,
		html.EscapeString(approvalSummary(a, findingTitle)), html.EscapeString(link), html.EscapeString(link))
}

// oneLineTitle bounds a finding title for a notification.
func oneLineTitle(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	const limit = 160
	if len(s) > limit {
		cut := limit
		for cut > 0 && (s[cut]&0xC0) == 0x80 {
			cut--
		}
		s = s[:cut] + "..."
	}
	return s
}

// NotifyApprovalSettingsChanged tells the organization's approvers (owners,
// administrators and holders of findings:approve), except the actor, that the
// approval settings changed. Best effort.
func (s *VulnerabilityService) NotifyApprovalSettingsChanged(ctx context.Context, tenantID, actorID, title, body string) {
	if s.approverDir == nil || s.approvalInApp == nil {
		return
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return
	}
	all, err := s.approverDir.FindingApprovers(ctx, tid)
	if err != nil {
		s.logger.Warn("approval settings notice: list approvers", "error", logger.SanitizeError(err))
		return
	}
	for _, ap := range all {
		if ap.UserID == actorID {
			continue
		}
		uid, err := shared.IDFromString(ap.UserID)
		if err != nil {
			continue
		}
		if err := s.approvalInApp.Notify(ctx, notificationdom.NotificationParams{
			TenantID: tid, Audience: notificationdom.AudienceUser, AudienceID: &uid,
			NotificationType: notificationdom.TypeFindingApproval, Title: title, Body: body,
			Severity: notificationdom.SeverityHigh, ResourceType: "settings", URL: "/settings/finding-approvals",
		}); err != nil {
			s.logger.Warn("approval settings notice: in-app", "error", logger.SanitizeError(err))
		}
	}
}

// maxVEXNoticeFindings bounds one VEX notice: how many findings are read
// for titles and how many titles are named.
const (
	maxVEXNoticeFindings = 1000
	maxVEXNoticeTitles   = 5
)

// NotifyVEXRequests tells the approvers about the false-positive requests
// VEX statements in one scan report made (a platform actor requested them;
// nobody is excluded as requester). Batched: each approver gets one in-app
// notice and one email per report, counting only the findings in their own
// data scope and naming at most a few of their titles; an approver who can
// see none of them is not told. Best effort: the requests exist already.
func (s *VulnerabilityService) NotifyVEXRequests(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID) {
	if s.approverDir == nil || len(findingIDs) == 0 {
		return
	}
	if len(findingIDs) > maxVEXNoticeFindings {
		findingIDs = findingIDs[:maxVEXNoticeFindings]
	}
	approvers, err := s.approverDir.FindingApprovers(ctx, tenantID)
	if err != nil {
		s.logger.Warn("vex notice: list approvers", "error", logger.SanitizeError(err))
		return
	}
	findings, err := s.findingRepo.GetByIDs(ctx, tenantID, findingIDs)
	if err != nil {
		s.logger.Warn("vex notice: read findings", "error", logger.SanitizeError(err))
		return
	}
	titles := make(map[shared.ID]string, len(findings))
	for _, f := range findings {
		if f.TenantID() == tenantID {
			titles[f.ID()] = f.Title()
		}
	}
	for _, ap := range approvers {
		uid, err := shared.IDFromString(ap.UserID)
		if err != nil {
			continue
		}
		visible := s.findingsVisibleTo(ctx, tenantID, uid, findingIDs)
		if len(visible) == 0 {
			continue
		}
		names := make([]string, 0, maxVEXNoticeTitles)
		for _, id := range visible {
			if t := oneLineTitle(titles[id]); t != "" && len(names) < maxVEXNoticeTitles {
				names = append(names, t)
			}
		}
		title := fmt.Sprintf("%d false-positive request(s) from VEX statements await a decision", len(visible))
		body := "A VEX statement in a scan report says the component is not affected; a person decides."
		if len(names) > 0 {
			body += " " + strings.Join(names, "; ")
			if len(visible) > len(names) {
				body += fmt.Sprintf(" and %d more", len(visible)-len(names))
			}
			body += "."
		}
		if s.approvalInApp != nil {
			if err := s.approvalInApp.Notify(ctx, notificationdom.NotificationParams{
				TenantID: tenantID, Audience: notificationdom.AudienceUser, AudienceID: &uid,
				NotificationType: notificationdom.TypeFindingApproval, Title: title, Body: body,
				Severity: notificationdom.SeverityMedium, ResourceType: "finding", URL: approvalInboxURL,
			}); err != nil {
				s.logger.Warn("vex notice: in-app", "error", logger.SanitizeError(err))
			}
		}
		if s.approvalMail != nil && ap.Email != "" {
			s.approvalMail.SendFindingApprovalMail(ctx, tenantID.String(), []string{ap.Email}, "[Findings] "+title,
				s.vexMailBody(len(visible), names))
		}
	}
}

// findingsVisibleTo keeps the findings in the user's data scope. Without a
// data-scope enforcer none is visible (fail closed): a notice must never
// name a finding nobody checked the recipient may see.
func (s *VulnerabilityService) findingsVisibleTo(ctx context.Context, tenantID, userID shared.ID, ids []shared.ID) []shared.ID {
	if s.dataScope == nil {
		return nil
	}
	scope, err := s.dataScope.ForUser(ctx, tenantID, userID)
	if err != nil {
		s.logger.Warn("vex notice: data scope", "error", logger.SanitizeError(err))
		return nil
	}
	in, err := s.dataScope.FilterFindings(ctx, scope, ids)
	if err != nil {
		s.logger.Warn("vex notice: data scope", "error", logger.SanitizeError(err))
		return nil
	}
	out := make([]shared.ID, 0, len(ids))
	for _, id := range ids {
		if in(id) {
			out = append(out, id)
		}
	}
	return out
}

// vexMailBody is the email of a VEX batch: the count and the titles the
// approver can see, escaped; the link only opens the inbox.
func (s *VulnerabilityService) vexMailBody(n int, titles []string) string {
	link := s.webBaseURL + approvalInboxURL
	var items strings.Builder
	for _, t := range titles {
		items.WriteString("<li>" + html.EscapeString(t) + "</li>")
	}
	list := ""
	if items.Len() > 0 {
		list = "<ul>" + items.String() + "</ul>"
	}
	return fmt.Sprintf(`<p>VEX statements in a scan report requested %d false positive(s) you may decide.</p>%s
<p>A person must approve or reject each one. Review them: <a href="%s">%s</a> (sign-in required).</p>`,
		n, list, html.EscapeString(link), html.EscapeString(link))
}

// vexNoticeOutbox claims the VEX requests nobody was told about yet
// (*postgres.FindingApprovalRepository).
type vexNoticeOutbox interface {
	ClaimUnnotifiedVEXRequests(ctx context.Context, limit int) (map[shared.ID][]shared.ID, error)
}

// DispatchVEXRequestNotices sends the batched notices for the requests VEX
// statements made since the last run: one per tenant and approver. Called by
// a background job, never on the ingest path. It answers how many requests
// it announced.
func (s *VulnerabilityService) DispatchVEXRequestNotices(ctx context.Context) (int, error) {
	outbox, ok := s.approvalRepo.(vexNoticeOutbox)
	if !ok || s.approverDir == nil {
		return 0, nil
	}
	byTenant, err := outbox.ClaimUnnotifiedVEXRequests(ctx, 0)
	if err != nil {
		return 0, err
	}
	n := 0
	for tid, ids := range byTenant {
		s.NotifyVEXRequests(ctx, tid, ids)
		n += len(ids)
	}
	return n, nil
}
