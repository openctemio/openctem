package jira

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketlink"
	"github.com/openctemio/openctem/api/pkg/domain/ticketmap"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Inbound status intents from a published mapping profile
// (docs/rfcs/RFC-097-ticket-field-mapping.md, "Status mapping"). The
// profile's inbound rules say what a tracker status means; each intent goes
// to a service path, never to a status written directly:
//
//	in_progress / reopen → the finding moves to in_progress (legal steps)
//	fix_claim            → "mark fixed": fix_applied, verification queued
//	request_accept / fp  → a pending risk-acceptance / false-positive request
//	                       (four-eyes); the finding does not move
//	suggest_duplicate    → nothing changes; a person reviews it in OpenCTEM
//	ignore               → nothing
//
// None of them closes a finding.

// handleProfileIntent applies the status change through the published
// finding profile of the issue's project. handled is false when the project
// has no published profile with inbound rules (the built-in map applies).
func (s *SyncService) handleProfileIntent(ctx context.Context, tenantID shared.ID, payload WebhookPayload, jiraStatus string) (bool, error) {
	if s.profiles == nil {
		return false, nil
	}
	client, err := s.resolveClient(ctx, tenantID)
	if err != nil {
		return false, nil //nolint:nilerr // no integration: the built-in path reports it
	}
	pc, ok := s.profileClient(client)
	if !ok {
		return false, nil
	}
	sm, err := s.profiles.InboundStatusMap(ctx, tenantID, pc.IntegrationID(), ticketmap.ObjectFinding, ticketlink.ProjectOf(payload.Issue.Key))
	if err != nil {
		// Fail closed: a profile exists or not; when it cannot be read, the
		// built-in map must not apply in its place. Jira retries the delivery.
		return true, fmt.Errorf("load the inbound status map: %w", err)
	}
	if sm == nil || len(sm.Inbound) == 0 {
		return false, nil
	}
	ev := statusEvent(payload)
	intent, mapped := sm.IntentFor(ev)
	if !mapped {
		s.logger.Warn("jira webhook: status not mapped by the profile; ignored",
			"issue_key", logger.SanitizeValue(payload.Issue.Key), "status_id", logger.SanitizeValue(ev.StatusID))
		return true, nil
	}
	switch intent {
	case ticketmap.IntentInProgress, ticketmap.IntentReopen:
		return true, s.applyToLinked(ctx, tenantID, payload, jiraStatus, vulnerability.FindingStatusInProgress)
	case ticketmap.IntentFixClaim:
		return true, s.applyToLinked(ctx, tenantID, payload, jiraStatus, vulnerability.FindingStatusFixApplied)
	case ticketmap.IntentRequestAccept:
		return true, s.requestFromTicket(ctx, tenantID, payload, jiraStatus, vulnerability.FindingStatusAccepted)
	case ticketmap.IntentRequestFP:
		return true, s.requestFromTicket(ctx, tenantID, payload, jiraStatus, vulnerability.FindingStatusFalsePositive)
	case ticketmap.IntentSuggestDuplicate:
		s.commentOnce(ctx, tenantID, payload.Issue.Key, jiraStatus,
			"OpenCTEM does not mark findings duplicate from a ticket: a person reviews and marks duplicates in OpenCTEM. The linked findings stay as they are.")
		return true, nil
	default:
		return true, nil
	}
}

// requestFromTicket opens pending disposition requests for the findings
// linked to the issue and tells the issue what happened.
func (s *SyncService) requestFromTicket(ctx context.Context, tenantID shared.ID, payload WebhookPayload, jiraStatus string, target vulnerability.FindingStatus) error {
	ids, err := s.linkedFindings(ctx, tenantID, deriveJiraTicketURL(payload.Issue))
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	if s.applier == nil {
		s.logger.Error("jira webhook: inbound status applier not wired; request not opened",
			"issue_key", logger.SanitizeValue(payload.Issue.Key))
		return nil
	}
	requested, pending, refused, err := s.applier.RequestTicketDisposition(ctx, tenantID, ids, target, "jira", payload.Issue.Key, payload.User.ID())
	if err != nil {
		return fmt.Errorf("request a disposition for linked findings: %w", err)
	}
	s.logger.Info("jira webhook requested a disposition",
		"issue_key", logger.SanitizeValue(payload.Issue.Key), "requested_status", target,
		"linked", len(ids), "requested", len(requested), "pending", len(pending), "refused", len(refused))

	what := "risk acceptance"
	if target == vulnerability.FindingStatusFalsePositive {
		what = "false positive"
	}
	var b strings.Builder
	if n := len(requested) + len(pending); n > 0 {
		fmt.Fprintf(&b, "%d linked finding(s) have a pending %s request in OpenCTEM. A person with the approve permission decides; until then the findings stay open.", n, what)
	}
	if len(refused) > 0 {
		if b.Len() > 0 {
			b.WriteString("\n\n")
		}
		fmt.Fprintf(&b, "No request was made for %d linked finding(s):", len(refused))
		for i, r := range refused {
			if i == maxRefusalLines {
				fmt.Fprintf(&b, "\n\n(and %d more)", len(refused)-i)
				break
			}
			b.WriteString("\n\n" + r.FindingID + ": " + r.Reason)
		}
	}
	if b.Len() > 0 {
		s.commentOnce(ctx, tenantID, payload.Issue.Key, jiraStatus, b.String())
	}
	return nil
}

// statusEvent reads the new status of a webhook: its id and category from
// the issue fields (else the changelog's status id) and the resolution.
func statusEvent(p WebhookPayload) ticketmap.StatusEvent {
	ev := ticketmap.StatusEvent{AuthorID: p.User.ID()}
	if st, ok := p.Issue.Fields["status"].(map[string]any); ok {
		ev.StatusID, _ = st["id"].(string)
		if cat, ok := st["statusCategory"].(map[string]any); ok {
			ev.Category, _ = cat["key"].(string)
		}
	}
	if res, ok := p.Issue.Fields["resolution"].(map[string]any); ok {
		ev.Resolution, _ = res["name"].(string)
	}
	if p.Changelog != nil {
		for _, it := range p.Changelog.Items {
			switch {
			case strings.EqualFold(it.Field, "status") && it.To != "":
				ev.StatusID = it.To // the change itself wins over the snapshot
			case strings.EqualFold(it.Field, "resolution") && ev.Resolution == "":
				ev.Resolution = it.ToString
			}
		}
	}
	return ev
}

// inboundProjectAllowed reports whether the issue is in a project configured
// for ticketing (the same rule as linking an existing issue): a change of an
// issue elsewhere in the integration's Jira moves nothing, even when a
// finding still names that issue by URL.
func (s *SyncService) inboundProjectAllowed(ctx context.Context, tenantID shared.ID, issueKey string) (bool, error) {
	client, err := s.resolveClient(ctx, tenantID)
	if err != nil {
		return true, nil //nolint:nilerr // no client: the applier path reports it; nothing reaches the tracker
	}
	ii, ok := client.(IssueIdentifier)
	if !ok {
		return true, nil
	}
	allowed, err := s.allowedProjects(ctx, tenantID, ii.IntegrationID())
	if err != nil {
		return false, err
	}
	return allowed[ticketlink.ProjectOf(strings.ToUpper(issueKey))], nil
}
