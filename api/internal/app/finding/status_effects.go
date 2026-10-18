package finding

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The side effects of a finding status change, in one place. Every route
// that changes a finding's status (the status PATCH, bulk status, the fix
// claim / verify / reject actions by id and by filter, approvals, ticket
// webhooks, VEX statements) ends in afterStatusChange with the findings its
// write actually moved, so each moved finding gets exactly one workflow
// event, one assignee notification, one outbound ticket sync and, for a fix
// claim, one proof-of-fix re-check, and a finding a guarded write left alone
// gets none.
//
// The timeline entry is not a side effect here: it is written with the move
// itself, by the status write's transition context (the database trigger,
// same transaction) or, for a person's move with lifecycle details, by the
// caller right after the write.

// StatusEffectsFunc runs the side effects of applied status moves and
// returns the number of proof-of-fix re-checks queued. Services outside
// VulnerabilityService (finding actions, VEX) are handed
// VulnerabilityService.AfterStatusMoves at the composition root.
type StatusEffectsFunc func(ctx context.Context, tenantID shared.ID, actorID string, moves []vulnerability.StatusMove) int

// statusChange is one applied move (old to new) with the finding it moved.
type statusChange struct {
	f        *vulnerability.Finding
	old, new vulnerability.FindingStatus
}

// AfterStatusMoves runs the side effects of moves a write applied, reading
// the moved findings back (tenant-scoped) for their assignee, ticket links and
// title. A move whose finding is gone is skipped.
func (s *VulnerabilityService) AfterStatusMoves(ctx context.Context, tenantID shared.ID, actorID string, moves []vulnerability.StatusMove) int {
	if len(moves) == 0 {
		return 0
	}
	ids := make([]shared.ID, 0, len(moves))
	for _, m := range moves {
		if m.Old != m.New {
			ids = append(ids, m.FindingID)
		}
	}
	if len(ids) == 0 {
		return 0
	}
	found, err := s.findingRepo.GetByIDs(ctx, tenantID, ids)
	if err != nil {
		s.logger.Warn("status side effects: read moved findings", "error", err, "count", len(ids))
		return 0
	}
	byID := make(map[shared.ID]*vulnerability.Finding, len(found))
	for _, f := range found {
		byID[f.ID()] = f
	}
	changes := make([]statusChange, 0, len(moves))
	for _, m := range moves {
		if f := byID[m.FindingID]; f != nil && m.Old != m.New {
			changes = append(changes, statusChange{f: f, old: m.Old, new: m.New})
		}
	}
	return s.afterStatusChange(ctx, tenantID, actorID, changes)
}

// afterStatusChange fires the side effects of applied moves (best effort:
// none of them undoes the move). A label change inside one status is not a
// status change and fires nothing. A move a ticket webhook made is not pushed
// back to the ticket.
func (s *VulnerabilityService) afterStatusChange(ctx context.Context, tenantID shared.ID, actorID string, changes []statusChange) int {
	_, ticketInbound := vulnerability.TicketInboundFrom(ctx)
	fixClaims := make([]shared.ID, 0)
	for _, c := range changes {
		newStatus := c.new
		if c.old == newStatus {
			continue
		}
		// Automation on finding_status_changed (for example a
		// verification scan on resolve); no-op when no workflow matches.
		if s.workflowStatusDispatch != nil {
			s.workflowStatusDispatch(ctx, tenantID, c.f, c.old.String(), newStatus.String())
		}
		s.notifyAssignee(ctx, c.f, actorID,
			notification.TypeFindingStatusChange,
			fmt.Sprintf("Finding status changed: %s → %s", c.old, newStatus),
			c.f.Message(),
		)
		// Outbound ticket sync only for findings with a work-item link; the
		// worker no-ops unless the tenant opted in.
		if !ticketInbound && s.jiraStatusSync != nil && len(c.f.WorkItemURIs()) > 0 {
			s.jiraStatusSync(ctx, tenantID, c.f.ID())
		}
		if newStatus == vulnerability.FindingStatusFixApplied {
			fixClaims = append(fixClaims, c.f.ID())
		}
	}
	// A fix claim is verified, not trusted: one proof-of-fix re-check per
	// finding that reached fix_applied (bounded, best effort).
	if len(fixClaims) > 0 && s.proofOfFix != nil {
		return s.proofOfFix(ctx, tenantID, fixClaims)
	}
	return 0
}

// afterApplied runs the side effects for findings an approval moved to
// status to in its own transaction (the write fails unless the finding
// moved, so an applied decision is a move). before holds the findings as
// they were read before the decision; one already in status to is not a
// move.
func (s *VulnerabilityService) afterApplied(ctx context.Context, tenantID shared.ID, actorID string, before []*vulnerability.Finding, to vulnerability.FindingStatus) {
	moves := make([]vulnerability.StatusMove, 0, len(before))
	for _, f := range before {
		if f != nil && f.Status() != to {
			moves = append(moves, vulnerability.StatusMove{FindingID: f.ID(), Old: f.Status(), New: to})
		}
	}
	s.AfterStatusMoves(ctx, tenantID, actorID, moves)
}

// moveStatusBatch runs a guarded batch status write and returns the
// findings it moved. A store that cannot report them (a test double) is
// written through UpdateStatusBatch(From) and every id counts as moved.
func moveStatusBatch(ctx context.Context, repo vulnerability.FindingRepository, tenantID shared.ID, ids []shared.ID,
	from []vulnerability.FindingStatus, status vulnerability.FindingStatus, resolution string, resolvedBy *shared.ID, closure vulnerability.Closure,
) ([]shared.ID, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	if w, ok := repo.(vulnerability.StatusMoveWriter); ok {
		return w.MoveStatusBatch(ctx, tenantID, ids, from, status, resolution, resolvedBy, closure)
	}
	if len(from) > 0 {
		w, ok := repo.(vulnerability.FixClaimBatchWriter)
		if !ok {
			return nil, fmt.Errorf("%w: the finding store cannot limit a batch to the findings' current status", shared.ErrValidation)
		}
		if err := w.UpdateStatusBatchFrom(ctx, tenantID, ids, from, status, resolution, resolvedBy, closure); err != nil {
			return nil, err
		}
		return ids, nil
	}
	if err := repo.UpdateStatusBatch(ctx, tenantID, ids, status, resolution, resolvedBy, closure); err != nil {
		return nil, err
	}
	return ids, nil
}

// movesOf pairs the moved ids with the status each was read in.
func movesOf(moved []shared.ID, old func(shared.ID) vulnerability.FindingStatus, to vulnerability.FindingStatus) []vulnerability.StatusMove {
	out := make([]vulnerability.StatusMove, 0, len(moved))
	for _, id := range moved {
		out = append(out, vulnerability.StatusMove{FindingID: id, Old: old(id), New: to})
	}
	return out
}
