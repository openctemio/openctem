package finding

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
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
	vulnerability.FindingStatusNew:         true,
	vulnerability.FindingStatusConfirmed:   true,
	vulnerability.FindingStatusInProgress:  true,
	vulnerability.FindingStatusFixApplied:  true,
	vulnerability.FindingStatusNotObserved: true,
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
func (s *VulnerabilityService) ApplyTicketStatus(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID,
	target vulnerability.FindingStatus, integration, ref string,
) (*TicketStatusOutcome, error) {
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
	ctx = vulnerability.WithStatusTransition(ctx, vulnerability.StatusTransition{
		Source:    integration,
		Reason:    "ticket_status",
		ActorType: IntegrationActorType,
	})
	note := fmt.Sprintf("%s %s moved to a status mapped to %s", integration, ref, target)

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
