package finding

// The daily digest of finding requests waiting for each approver, and of
// the decisions one person made alone in the last day
// (api/docs/architecture/finding-status-lifecycle.md, "Approvals").
//
// Threat model: the digest changes nobody's power; it reminds, and it makes
// every single-person decision (a false positive or accepted risk decided
// under the organization's level, or the sole member's own approval) visible
// to the other approvers. What it may leak is bounded like every approval
// notice: an approver is counted only the requests they may decide and the
// decisions of others (not their own, the finding in their data scope),
// titles are those of findings they can see, never justifications or
// evidence; service accounts are never sent one; it goes at most once a day
// per approver and organization, and muting the digest notification type
// opts out of it (in-app and email).

import (
	"context"
	"fmt"
	"html"
	"strings"
	"time"

	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/weblink"
)

// ApprovalDigestInterval is the shortest time between two digests of one
// approver in one organization.
const ApprovalDigestInterval = 23 * time.Hour

// maxDigestTitles is how many request titles one digest names.
const maxDigestTitles = 5

// DecidedAloneWindow is how far back a digest looks for decisions one
// person made: a day, a little more than ApprovalDigestInterval so no
// decision falls between two digests.
const DecidedAloneWindow = 24 * time.Hour

// decidedAloneStore lists the decisions one person made since a time
// (*postgres.FindingApprovalRepository).
type decidedAloneStore interface {
	DecidedAloneSince(ctx context.Context, since time.Time, limit int) ([]*vulnerability.Approval, error)
}

// approvalDigestStore lists pending requests and records sent digests
// (*postgres.FindingApprovalRepository).
type approvalDigestStore interface {
	PendingForDigest(ctx context.Context, limit int) ([]*vulnerability.Approval, error)
	MarkDigestSent(ctx context.Context, tenantID, userID shared.ID, minInterval time.Duration) (bool, error)
}

// NotificationPreferenceReader reads a member's notification preferences
// (*postgres.NotificationRepository).
type NotificationPreferenceReader interface {
	GetPreferences(ctx context.Context, tenantID, userID shared.ID) (*notificationdom.Preferences, error)
}

// SetApprovalDigestPreferences wires the preference read that lets a member
// opt out of the digest (nil: everyone gets it).
func (s *VulnerabilityService) SetApprovalDigestPreferences(p NotificationPreferenceReader) {
	s.digestPrefs = p
}

// SendApprovalDigests sends the daily digest to every approver who has
// requests waiting for them or whom another person's decision made alone in
// the last DecidedAloneWindow concerns, at most once per
// ApprovalDigestInterval. It answers how many digests it sent. A background
// job (no request user).
func (s *VulnerabilityService) SendApprovalDigests(ctx context.Context) (int, error) {
	store, ok := s.approvalRepo.(approvalDigestStore)
	if !ok || s.approverDir == nil {
		return 0, nil
	}
	pending, err := store.PendingForDigest(ctx, 0)
	if err != nil {
		return 0, err
	}
	var alone []*vulnerability.Approval
	if ds, ok := s.approvalRepo.(decidedAloneStore); ok {
		if alone, err = ds.DecidedAloneSince(ctx, time.Now().Add(-DecidedAloneWindow), 0); err != nil {
			return 0, err
		}
	}
	byTenant := map[shared.ID][]*vulnerability.Approval{}
	aloneByTenant := map[shared.ID][]*vulnerability.Approval{}
	order := []shared.ID{}
	seen := map[shared.ID]bool{}
	for _, a := range pending {
		if !seen[a.TenantID] {
			seen[a.TenantID] = true
			order = append(order, a.TenantID)
		}
		byTenant[a.TenantID] = append(byTenant[a.TenantID], a)
	}
	for _, a := range alone {
		if !seen[a.TenantID] {
			seen[a.TenantID] = true
			order = append(order, a.TenantID)
		}
		aloneByTenant[a.TenantID] = append(aloneByTenant[a.TenantID], a)
	}
	sent := 0
	for _, tid := range order {
		n, err := s.sendTenantDigests(ctx, store, tid, byTenant[tid], aloneByTenant[tid])
		if err != nil {
			s.logger.Warn("approval digest: tenant", "tenant_id", tid.String(), "error", logger.SanitizeError(err))
			continue
		}
		sent += n
	}
	return sent, nil
}

func (s *VulnerabilityService) sendTenantDigests(ctx context.Context, store approvalDigestStore, tid shared.ID,
	pending, alone []*vulnerability.Approval,
) (int, error) {
	approvers, err := s.approverDir.FindingApprovers(ctx, tid)
	if err != nil {
		return 0, err
	}
	ids := make([]shared.ID, 0, len(pending)+len(alone))
	for _, a := range pending {
		ids = append(ids, a.FindingID)
	}
	for _, a := range alone {
		ids = append(ids, a.FindingID)
	}
	findings, err := s.findingRepo.GetByIDs(ctx, tid, ids)
	if err != nil {
		return 0, err
	}
	titles := make(map[shared.ID]string, len(findings))
	for _, f := range findings {
		if f.TenantID() == tid {
			titles[f.ID()] = f.Title()
		}
	}
	now := time.Now()
	sent := 0
	for _, ap := range approvers {
		uid, err := shared.IDFromString(ap.UserID)
		if err != nil {
			continue
		}
		mine := s.decidableBy(ctx, tid, uid, pending)
		// Decisions of others made alone: the same rule (not their own, the
		// finding in their data scope).
		others := s.decidableBy(ctx, tid, uid, alone)
		if (len(mine) == 0 && len(others) == 0) || s.digestMuted(ctx, tid, uid) {
			continue
		}
		ok, err := store.MarkDigestSent(ctx, tid, uid, ApprovalDigestInterval)
		if err != nil || !ok {
			continue
		}
		soon, names := 0, make([]string, 0, maxDigestTitles)
		for _, a := range mine {
			if a.DecideBy != nil && a.DecideBy.Sub(now) < 48*time.Hour {
				soon++
			}
			if t := oneLineTitle(titles[a.FindingID]); t != "" && len(names) < maxDigestTitles {
				names = append(names, statusLabel(a.RequestedStatus)+": "+t)
			}
		}
		aloneNames := make([]string, 0, maxDigestTitles)
		for _, a := range others {
			if t := oneLineTitle(titles[a.FindingID]); t != "" && len(aloneNames) < maxDigestTitles {
				aloneNames = append(aloneNames, statusLabel(a.RequestedStatus)+": "+t)
			}
		}
		s.deliverDigest(ctx, tid, uid, ap.Email, digestCounts{pending: len(mine), soon: soon, alone: len(others)}, names, aloneNames)
		sent++
	}
	return sent, nil
}

// decidableBy keeps the requests the user may decide (or, for decisions,
// may see): not their own, and the finding in their data scope.
func (s *VulnerabilityService) decidableBy(ctx context.Context, tid, uid shared.ID, pending []*vulnerability.Approval) []*vulnerability.Approval {
	ids := make([]shared.ID, 0, len(pending))
	for _, a := range pending {
		if a.RequestedBy.IsZero() || a.RequestedBy != uid {
			ids = append(ids, a.FindingID)
		}
	}
	visible := map[shared.ID]bool{}
	for _, id := range s.findingsVisibleTo(ctx, tid, uid, ids) {
		visible[id] = true
	}
	out := make([]*vulnerability.Approval, 0, len(ids))
	for _, a := range pending {
		if (a.RequestedBy.IsZero() || a.RequestedBy != uid) && visible[a.FindingID] {
			out = append(out, a)
		}
	}
	return out
}

// digestMuted reports whether the member muted the digest (an unreadable
// preference counts as not muted: the digest only reminds).
func (s *VulnerabilityService) digestMuted(ctx context.Context, tid, uid shared.ID) bool {
	if s.digestPrefs == nil {
		return false
	}
	p, err := s.digestPrefs.GetPreferences(ctx, tid, uid)
	return err == nil && p != nil && p.IsTypeMuted(notificationdom.TypeFindingApprovalDigest)
}

// digestCounts are the numbers one digest reports.
type digestCounts struct {
	// pending requests the approver may decide, soon of them expiring
	// within two days; alone: decisions others made by themselves in the
	// last DecidedAloneWindow.
	pending, soon, alone int
}

func (s *VulnerabilityService) deliverDigest(ctx context.Context, tid, uid shared.ID, email string, n digestCounts, names, aloneNames []string) {
	total, soon := n.pending, n.soon
	title := fmt.Sprintf("%d finding request(s) wait for your decision", total)
	if total == 0 {
		title = fmt.Sprintf("%d finding decision(s) were made by one person", n.alone)
	}
	body := title + "."
	if total > 0 && soon > 0 {
		body += fmt.Sprintf(" %d expire within two days.", soon)
	}
	if len(names) > 0 {
		body += " " + strings.Join(names, "; ") + "."
	}
	if total > 0 && n.alone > 0 {
		body += fmt.Sprintf(" %d decision(s) were made by one person in the last day.", n.alone)
	}
	if len(aloneNames) > 0 {
		body += " Decided by one person: " + strings.Join(aloneNames, "; ") + "."
	}
	if s.approvalInApp != nil {
		if err := s.approvalInApp.Notify(ctx, notificationdom.NotificationParams{
			TenantID: tid, Audience: notificationdom.AudienceUser, AudienceID: &uid,
			NotificationType: notificationdom.TypeFindingApprovalDigest, Title: title, Body: body,
			Severity: notificationdom.SeverityLow, ResourceType: "finding", URL: approvalInboxURL,
		}); err != nil {
			s.logger.Warn("approval digest: in-app", "error", logger.SanitizeError(err))
		}
	}
	if s.approvalMail == nil || email == "" {
		return
	}
	link := weblink.Console(s.webBaseURL, approvalInboxURL, tid.String())
	var items strings.Builder
	for _, n := range names {
		items.WriteString("<li>" + html.EscapeString(n) + "</li>")
	}
	list := ""
	if items.Len() > 0 {
		list = "<ul>" + items.String() + "</ul>"
	}
	expiring := ""
	if soon > 0 {
		expiring = fmt.Sprintf("<p>%d of them expire within two days if nobody decides.</p>", soon)
	}
	decided := ""
	if n.alone > 0 {
		var ai strings.Builder
		for _, nm := range aloneNames {
			ai.WriteString("<li>" + html.EscapeString(nm) + "</li>")
		}
		decided = fmt.Sprintf("<p>%d decision(s) were made by one person in the last day, under the organization's approval levels or as its only member.</p>", n.alone)
		if ai.Len() > 0 {
			decided += "<ul>" + ai.String() + "</ul>"
		}
	}
	waiting := ""
	if total > 0 {
		waiting = fmt.Sprintf("<p>%d finding request(s) wait for your decision.</p>", total)
	}
	mailBody := fmt.Sprintf(`%s%s%s%s
<p>Review them: <a href="%s">%s</a> (sign-in required). To stop this daily summary, mute "Approvals digest" in your notification settings.</p>`,
		waiting, expiring, list, decided, html.EscapeString(link), html.EscapeString(link))
	s.approvalMail.SendFindingApprovalMail(ctx, tid.String(), []string{email}, "[Findings] "+title, mailBody)
}
