package jira

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketlink"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// External participant (research 220 §5.2,
// docs/architecture/ticketing-integration.md "External assignee"): the
// tracker's assignee of a linked issue is stored on the link as a label
// (account id and display name), with the issue's status category, from
// every inbound delivery of the integration that owns the issue. It is never
// written as a platform assignee, never counted as a member and grants no
// data access; the task or finding owner stays accountable.

// externalChangeOf reads the tracker-side change of a delivery: the
// assignee when the changelog changes it (an unassign sets it empty), and
// the issue's status category when the payload carries it. ok is false when
// the delivery says nothing about either.
func externalChangeOf(p WebhookPayload) (ticketlink.ExternalChange, bool) {
	ch := ticketlink.ExternalChange{At: time.Now().UTC()}
	if p.Timestamp > 0 {
		ch.At = time.UnixMilli(p.Timestamp).UTC()
	}
	if p.Changelog != nil {
		for _, it := range p.Changelog.Items {
			if !strings.EqualFold(it.Field, "assignee") {
				continue
			}
			ch.AssigneeSet = true
			ch.AssigneeID, ch.AssigneeName = it.To, it.ToString
			// The issue snapshot carries the same account with its display
			// name; prefer it when the changelog's id is the same or empty.
			if a, ok := p.Issue.Fields["assignee"].(map[string]any); ok && it.To != "" {
				id, _ := a["accountId"].(string)
				if id == "" {
					id, _ = a["name"].(string)
				}
				if name, _ := a["displayName"].(string); name != "" && (id == it.To || it.ToString == "") {
					ch.AssigneeName = name
				}
			}
			if it.To == "" {
				ch.AssigneeName = ""
			}
		}
	}
	if st, ok := p.Issue.Fields["status"].(map[string]any); ok {
		if cat, ok := st["statusCategory"].(map[string]any); ok {
			key, _ := cat["key"].(string)
			ch.StatusCategory = ticketlink.StatusCategoryFromJira(key)
		}
	}
	ch.AssigneeID = ticketlink.SanitizeExternalID(ch.AssigneeID)
	ch.AssigneeName = ticketlink.SanitizeExternalName(ch.AssigneeName)
	return ch, ch.AssigneeSet || ch.StatusCategory != ""
}

// RecordExternalChange stores the tracker-side change of an inbound delivery
// (assignee, status category) on the links of the issue in the integration
// the delivery was verified for: matched by the issue's id, or by key for
// links that recorded no id. It runs for every delivery, with or without a
// status change, and never touches a finding or a task.
func (s *SyncService) RecordExternalChange(ctx context.Context, tenantID, integrationID shared.ID, payload WebhookPayload) error {
	if s.links == nil || integrationID.IsZero() {
		return nil
	}
	ch, ok := externalChangeOf(payload)
	if !ok {
		return nil
	}
	key := strings.ToUpper(strings.TrimSpace(payload.Issue.Key))
	if !ticketlink.ValidKey(key) {
		key = ""
	}
	issueID := strings.TrimSpace(payload.Issue.ID)
	if len(issueID) > 64 {
		return nil
	}
	updated, err := s.links.RecordExternal(ctx, tenantID, integrationID, issueID, key, ch)
	if err != nil {
		return fmt.Errorf("record the issue's tracker state: %w", err)
	}
	if len(updated) > 0 && ch.AssigneeSet {
		s.logger.Info("jira webhook: external assignee recorded",
			"issue_key", logger.SanitizeValue(key), "links", len(updated), "assigned", ch.AssigneeID != "")
	}
	return nil
}
