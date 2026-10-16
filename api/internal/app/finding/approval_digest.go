package finding

// The daily digest of finding requests waiting for each approver
// (api/docs/architecture/finding-status-lifecycle.md, "Approvals").
//
// Threat model: the digest changes nobody's power; it only reminds. What it
// may leak is bounded like every approval notice: an approver is counted
// only the requests they may decide (not their own, the finding in their data
// scope), titles are those of findings they can see, never justifications or
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
)

// ApprovalDigestInterval is the shortest time between two digests of one
// approver in one organization.
const ApprovalDigestInterval = 23 * time.Hour

// maxDigestTitles is how many request titles one digest names.
const maxDigestTitles = 5

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
// requests waiting for them, at most once per ApprovalDigestInterval. It
// answers how many digests it sent. A background job (no request user).
func (s *VulnerabilityService) SendApprovalDigests(ctx context.Context) (int, error) {
	store, ok := s.approvalRepo.(approvalDigestStore)
	if !ok || s.approverDir == nil {
		return 0, nil
	}
	pending, err := store.PendingForDigest(ctx, 0)
	if err != nil {
		return 0, err
	}
	byTenant := map[shared.ID][]*vulnerability.Approval{}
	order := []shared.ID{}
	for _, a := range pending {
		if _, seen := byTenant[a.TenantID]; !seen {
			order = append(order, a.TenantID)
		}
		byTenant[a.TenantID] = append(byTenant[a.TenantID], a)
	}
	sent := 0
	for _, tid := range order {
		n, err := s.sendTenantDigests(ctx, store, tid, byTenant[tid])
		if err != nil {
			s.logger.Warn("approval digest: tenant", "tenant_id", tid.String(), "error", logger.SanitizeError(err))
			continue
		}
		sent += n
	}
	return sent, nil
}

func (s *VulnerabilityService) sendTenantDigests(ctx context.Context, store approvalDigestStore, tid shared.ID, pending []*vulnerability.Approval) (int, error) {
	approvers, err := s.approverDir.FindingApprovers(ctx, tid)
	if err != nil {
		return 0, err
	}
	ids := make([]shared.ID, 0, len(pending))
	for _, a := range pending {
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
		if len(mine) == 0 || s.digestMuted(ctx, tid, uid) {
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
		s.deliverDigest(ctx, tid, uid, ap.Email, len(mine), soon, names)
		sent++
	}
	return sent, nil
}

// decidableBy keeps the requests the user may decide: not their own, and
// the finding in their data scope.
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

func (s *VulnerabilityService) deliverDigest(ctx context.Context, tid, uid shared.ID, email string, total, soon int, names []string) {
	title := fmt.Sprintf("%d finding request(s) wait for your decision", total)
	body := title + "."
	if soon > 0 {
		body += fmt.Sprintf(" %d expire within two days.", soon)
	}
	if len(names) > 0 {
		body += " " + strings.Join(names, "; ") + "."
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
	link := s.webBaseURL + approvalInboxURL
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
	mailBody := fmt.Sprintf(`<p>%d finding request(s) wait for your decision.</p>%s%s
<p>Review them: <a href="%s">%s</a> (sign-in required). To stop this daily summary, mute "Approvals digest" in your notification settings.</p>`,
		total, expiring, list, html.EscapeString(link), html.EscapeString(link))
	s.approvalMail.SendFindingApprovalMail(ctx, tid.String(), []string{email}, "[Findings] "+title, mailBody)
}
