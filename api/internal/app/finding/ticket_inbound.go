package finding

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/activity"
	"github.com/openctemio/openctem/api/internal/app/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/safetext"
)

// Inbound ticket status changes (a linked Jira issue moved, a GitHub issue
// closed) go through the same rules as a person's bulk change: tenant and
// data scope, the transition map, the pentest and approval gates, and the
// "mark fixed" path. The integration is the recorded actor
// (StatusTransition with ActorType "integration"); it may only move a
// finding along the open statuses and claim a fix, never close one. A claim
// queues the proof-of-fix re-check, and a retest, a covered scan or a
// reviewer decides.

// TicketStatusOutcome is the result of applying a ticket's status to the
// findings linked to it.
type TicketStatusOutcome struct {
	// Applied are the findings now at the target status (changed by this
	// call).
	Applied []shared.ID
	// Unchanged are the findings already at the target.
	Unchanged []shared.ID
	// Refused are the findings the rules kept where they are, with the
	// reason (commented back on the ticket).
	Refused []BulkRowResult
}

// ticketOpenStatuses are the statuses an inbound ticket may move a finding
// between (and the only ones it may move a finding from).
var ticketOpenStatuses = map[vulnerability.FindingStatus]bool{
	vulnerability.FindingStatusNew:        true,
	vulnerability.FindingStatusConfirmed:  true,
	vulnerability.FindingStatusInProgress: true,
	vulnerability.FindingStatusFixApplied: true,
}

// TicketPath returns the legal steps from one open status to an inbound
// ticket target through open statuses only (shortest path over
// vulnerability.ValidStatusTransitions), excluding from. ok is false when
// there is none (a closed source, or a target a ticket may not set).
func TicketPath(from, to vulnerability.FindingStatus) ([]vulnerability.FindingStatus, bool) {
	if !ticketOpenStatuses[from] || !to.IsTicketInboundTarget() {
		return nil, false
	}
	if from == to {
		return nil, true
	}
	prev := map[vulnerability.FindingStatus]vulnerability.FindingStatus{}
	seen := map[vulnerability.FindingStatus]bool{from: true}
	queue := []vulnerability.FindingStatus{from}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range vulnerability.ValidStatusTransitions[cur] {
			if seen[next] || !ticketOpenStatuses[next] {
				continue
			}
			seen[next] = true
			prev[next] = cur
			if next == to {
				path := []vulnerability.FindingStatus{to}
				for p := prev[to]; p != from; p = prev[p] {
					path = append([]vulnerability.FindingStatus{p}, path...)
				}
				return path, true
			}
			queue = append(queue, next)
		}
	}
	return nil, false
}

// ApplyTicketStatus moves the tenant's findings linked to a ticket to the
// status the ticket now maps to. integration names the tracker ("jira"),
// ref the ticket ("OPS-12"). A fix_applied target is a "mark fixed" (legal
// steps, proof-of-fix queued); in_progress and confirmed walk the legal
// open steps. A closing target is refused for every finding.
//
// externalActor is the tracker account that moved the ticket (a Jira
// accountId); it is recorded in each step's timeline entry and the note.
func (s *VulnerabilityService) ApplyTicketStatus(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID,
	target vulnerability.FindingStatus, integration, ref, externalActor string,
) (*TicketStatusOutcome, error) {
	if !vulnerability.IsTicketInboundSource(integration) {
		return nil, fmt.Errorf("%w: unknown ticket integration", shared.ErrValidation)
	}
	out := &TicketStatusOutcome{}
	if len(findingIDs) == 0 {
		return out, nil
	}
	if !target.IsTicketInboundTarget() {
		for _, id := range findingIDs {
			out.Refused = append(out.Refused, BulkRowResult{FindingID: id.String(), Outcome: BulkRowFailed,
				Reason: "a ticket never closes a finding: a retest, a covered scan or a reviewer verifies the fix"})
		}
		return out, nil
	}
	ctx = vulnerability.WithTicketInbound(ctx, integration)
	ctx = vulnerability.WithStatusTransition(ctx, TicketTransition(integration, ref, externalActor))
	note := fmt.Sprintf("%s %s moved to a status mapped to %s", integration, ref, target)
	if externalActor != "" {
		note += " by " + integration + " account " + externalActor
	}

	findings, err := s.findingRepo.GetByIDs(ctx, tenantID, findingIDs)
	if err != nil {
		return nil, fmt.Errorf("load linked findings: %w", err)
	}
	current := make(map[shared.ID]vulnerability.FindingStatus, len(findings))
	for _, f := range findings {
		current[f.ID()] = f.Status()
	}
	pending := make([]shared.ID, 0, len(findingIDs))
	for _, id := range findingIDs {
		st, ok := current[id]
		switch {
		case !ok:
			out.Refused = append(out.Refused, BulkRowResult{FindingID: id.String(), Outcome: BulkRowFailed, Reason: "not found"})
		case st == target:
			out.Unchanged = append(out.Unchanged, id)
		default:
			if _, ok := TicketPath(st, target); !ok {
				out.Refused = append(out.Refused, BulkRowResult{FindingID: id.String(), Outcome: BulkRowFailed,
					Reason: fmt.Sprintf("the finding is %s; a ticket does not move it to %s (change it in the platform)", st, target)})
				continue
			}
			pending = append(pending, id)
		}
	}
	if len(pending) == 0 {
		return out, nil
	}

	if target == vulnerability.FindingStatusFixApplied {
		res, err := s.BulkUpdateFindingsStatus(ctx, tenantID.String(), BulkUpdateStatusInput{
			FindingIDs:            idStrings(pending),
			Status:                target.String(),
			Resolution:            note,
			HasFixApplyPermission: true,
			WalkToFixApplied:      true,
		})
		if err != nil {
			return nil, err
		}
		out.collect(pending, res)
		return out, nil
	}

	// in_progress / confirmed: one legal step per round (at most three), each
	// a bulk move through the same rules.
	for round := 0; round < 4 && len(pending) > 0; round++ {
		byStep := map[vulnerability.FindingStatus][]shared.ID{}
		for _, id := range pending {
			path, _ := TicketPath(current[id], target)
			if len(path) == 0 {
				continue
			}
			byStep[path[0]] = append(byStep[path[0]], id)
		}
		next := make([]shared.ID, 0, len(pending))
		for step, ids := range byStep {
			res, err := s.BulkUpdateFindingsStatus(ctx, tenantID.String(), BulkUpdateStatusInput{
				FindingIDs: idStrings(ids),
				Status:     step.String(),
				Resolution: note,
			})
			if err != nil {
				return nil, err
			}
			failed := map[string]string{}
			for _, r := range res.Rows {
				failed[r.FindingID] = r.Reason
			}
			for _, id := range ids {
				if reason, bad := failed[id.String()]; bad {
					out.Refused = append(out.Refused, BulkRowResult{FindingID: id.String(), Outcome: BulkRowFailed, Reason: reason})
					continue
				}
				current[id] = step
				if step == target {
					out.Applied = append(out.Applied, id)
				} else {
					next = append(next, id)
				}
			}
		}
		pending = next
	}
	return out, nil
}

// TicketTransition is the timeline record of an inbound ticket move: the
// integration as the actor, the ticket and the tracker account that moved it.
func TicketTransition(integration, ref, externalActor string) vulnerability.StatusTransition {
	t := vulnerability.StatusTransition{
		Source:    integration,
		Reason:    "ticket_status",
		ActorType: IntegrationActorType,
		ActorName: integration,
		Changes:   map[string]any{"ticket": ref},
	}
	if externalActor != "" {
		t.ActorName = integration + ":" + externalActor
		t.Changes[integration+"_account_id"] = externalActor
	}
	return t
}

// collect sorts a bulk result into applied, unchanged and refused findings.
func (o *TicketStatusOutcome) collect(ids []shared.ID, res *BulkUpdateResult) {
	rows := make(map[string]BulkRowResult, len(res.Rows))
	for _, r := range res.Rows {
		rows[r.FindingID] = r
	}
	for _, id := range ids {
		r, ok := rows[id.String()]
		switch {
		case !ok:
			o.Applied = append(o.Applied, id)
		case r.Outcome == BulkRowSkipped:
			o.Unchanged = append(o.Unchanged, id)
		default:
			o.Refused = append(o.Refused, r)
		}
	}
}

func idStrings(ids []shared.ID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

// TicketRequestOutcome is the result of a ticket asking for a disposition.
type TicketRequestOutcome struct {
	// Requested are the findings that now have a pending request.
	Requested []shared.ID
	// Pending are the findings that already had a pending request (the
	// ticket's ask is covered by it).
	Pending []shared.ID
	// Refused are the findings a request cannot be made for, with the reason.
	Refused []BulkRowResult
}

// RequestTicketDisposition records a linked ticket's ask to accept the risk
// of, or mark false positive, the findings linked to it (a Jira issue moved
// to "Won't Do"). It never closes a finding: an in-progress finding goes
// back to confirmed (the work stopped), and each request is pending, made
// by the ticket actor (no person, so any approver may decide it), and a
// person with findings:approve decides. A finding that already has a pending
// request keeps it; a closed finding, a pentest finding or a move the
// lifecycle does not allow is refused with the reason.
func (s *VulnerabilityService) RequestTicketDisposition(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID,
	target vulnerability.FindingStatus, integration, ref, externalActor string,
) (*TicketRequestOutcome, error) {
	if !vulnerability.IsTicketInboundSource(integration) {
		return nil, fmt.Errorf("%w: unknown ticket integration", shared.ErrValidation)
	}
	if target != vulnerability.FindingStatusAccepted && target != vulnerability.FindingStatusFalsePositive {
		return nil, fmt.Errorf("%w: a ticket requests a risk acceptance or a false positive only", shared.ErrValidation)
	}
	if s.approvalRepo == nil {
		return nil, fmt.Errorf("%w: approval workflow not configured", shared.ErrValidation)
	}
	out := &TicketRequestOutcome{}
	if len(findingIDs) == 0 {
		return out, nil
	}
	findings, err := s.findingRepo.GetByIDs(ctx, tenantID, findingIDs)
	if err != nil {
		return nil, fmt.Errorf("load linked findings: %w", err)
	}
	byID := make(map[shared.ID]*vulnerability.Finding, len(findings))
	for _, f := range findings {
		byID[f.ID()] = f
	}
	justification := ticketRequestJustification(integration, ref, externalActor, target)
	for _, id := range findingIDs {
		f, ok := byID[id]
		if !ok {
			out.Refused = append(out.Refused, BulkRowResult{FindingID: id.String(), Outcome: BulkRowFailed, Reason: "not found"})
			continue
		}
		// Work on an in-progress finding stopped: it goes back to confirmed
		// (a work-state move a ticket may report), where the disposition can
		// be requested. It moves only once its request exists.
		from := f.Status()
		if from == vulnerability.FindingStatusInProgress {
			from = vulnerability.FindingStatusConfirmed
		}
		if f.Source() == vulnerability.FindingSourcePentest || !from.CanTransitionTo(target) {
			out.Refused = append(out.Refused, BulkRowResult{FindingID: id.String(), Outcome: BulkRowFailed,
				Reason: fmt.Sprintf("the finding is %s; a request for %s cannot be made for it", f.Status(), target)})
			continue
		}
		existing, err := s.approvalRepo.ListByFinding(ctx, tenantID, id)
		if err != nil {
			return nil, err
		}
		pending := false
		for _, a := range existing {
			if a.IsPending() {
				pending = true
				break
			}
		}
		if pending {
			out.Pending = append(out.Pending, id)
			continue
		}
		approval, err := vulnerability.NewActorApproval(tenantID, id, vulnerability.ApprovalActorTicket, string(target), justification)
		if err != nil {
			return nil, err
		}
		if target == vulnerability.FindingStatusAccepted {
			// An accepted risk always ends: the default for the finding's
			// priority (the approver sees it and may reject instead).
			approval.ExpiresAt, _ = vulnerability.AcceptanceEnd(nil, time.Now(), priorityClassString(f), f.IsInKEV())
		}
		if err := s.approvalRepo.Create(ctx, approval); err != nil {
			if errors.Is(err, shared.ErrConflict) {
				out.Pending = append(out.Pending, id) // another delivery asked first
				continue
			}
			return nil, err
		}
		if f.Status() == vulnerability.FindingStatusInProgress {
			if reason, moved := s.stopWorkForRequest(ctx, tenantID, id, integration, ref, externalActor); !moved {
				// The finding stays where it is, and so does no request.
				if cerr := approval.Cancel(); cerr == nil {
					if uerr := s.approvalRepo.Update(ctx, approval); uerr != nil {
						return nil, fmt.Errorf("withdraw the request of a finding that could not move: %w", uerr)
					}
				}
				out.Refused = append(out.Refused, BulkRowResult{FindingID: id.String(), Outcome: BulkRowFailed, Reason: reason})
				continue
			}
		}
		out.Requested = append(out.Requested, id)
		s.recordTicketRequest(ctx, tenantID, id, approval, integration, ref)
	}
	return out, nil
}

// stopWorkForRequest moves an in-progress finding back to confirmed after
// its request was created. It reports the refusal reason when the move did
// not happen.
func (s *VulnerabilityService) stopWorkForRequest(ctx context.Context, tenantID, id shared.ID, integration, ref, externalActor string) (string, bool) {
	back, err := s.ApplyTicketStatus(ctx, tenantID, []shared.ID{id}, vulnerability.FindingStatusConfirmed, integration, ref, externalActor)
	if err != nil {
		s.logger.Warn("ticket request: moving the finding back to confirmed failed", "finding_id", id.String(), "error", err)
		return "the finding could not be moved back to confirmed; try again", false
	}
	if len(back.Refused) > 0 {
		return back.Refused[0].Reason, false
	}
	return "", true
}

// recordTicketRequest writes the timeline entry and the approvers'
// notification of a ticket's request. Best effort: the request stands.
func (s *VulnerabilityService) recordTicketRequest(ctx context.Context, tenantID, findingID shared.ID, approval *vulnerability.Approval, integration, ref string) {
	if s.activityService != nil {
		if _, err := s.activityService.RecordActivity(ctx, activity.RecordActivityInput{
			TenantID:     tenantID.String(),
			FindingID:    findingID.String(),
			ActivityType: string(vulnerability.ActivityApprovalRequested),
			ActorType:    string(vulnerability.ActorTypeIntegration),
			Changes: map[string]interface{}{
				"requested_status": approval.RequestedStatus,
				"requested_by":     vulnerability.ApprovalActorTicket,
				"approval_id":      approval.ID.String(),
				"integration":      integration,
				"ticket":           ref,
			},
			Source: string(vulnerability.SourceWebhook),
		}); err != nil {
			s.logger.Warn("failed to record ticket request activity", "error", err)
		}
	}
	if s.notificationService != nil {
		approvalUUID, _ := uuid.Parse(approval.ID.String())
		if err := s.notificationService.Enqueue(ctx, outbox.EnqueueParams{
			TenantID:      tenantID,
			EventType:     "approval_requested",
			AggregateType: "approval",
			AggregateID:   &approvalUUID,
			Title:         "A linked ticket requests: " + approval.RequestedStatus,
			Body:          "A linked ticket was closed without a fix. A person must approve or reject the request.",
			Severity:      "low",
		}); err != nil {
			s.logger.Warn("failed to enqueue ticket request notification", "error", err)
		}
	}
}

// ticketRequestJustification is the request's justification: which ticket
// asked, and who moved it. Ticket text is never copied in (it is not the
// platform's to trust); the approver opens the ticket.
func ticketRequestJustification(integration, ref, externalActor string, target vulnerability.FindingStatus) string {
	what := "a risk acceptance"
	if target == vulnerability.FindingStatusFalsePositive {
		what = "a false positive"
	}
	j := fmt.Sprintf("%s %s was closed without a fix; it requests %s.", integration, safetext.SingleLine(ref, 64), what)
	if externalActor != "" {
		j += fmt.Sprintf(" Moved by %s account %s.", integration, safetext.SingleLine(externalActor, 128))
	}
	return j + " Check the finding and the ticket before you decide."
}
