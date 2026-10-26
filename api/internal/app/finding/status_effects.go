package finding

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/participation"
	"github.com/openctemio/openctem/api/pkg/domain/durablejob"
	"github.com/openctemio/openctem/api/pkg/domain/notification"
	participationdom "github.com/openctemio/openctem/api/pkg/domain/participation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
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

// StatusEffects is the side-effect path services outside
// VulnerabilityService (finding actions, VEX) are handed at the composition
// root; VulnerabilityService implements it.
type StatusEffects interface {
	// TicketSyncContext puts the outbound ticket status pushes of the linked
	// findings among ids on ctx; the status write queues them in its own
	// transaction for the findings it moves.
	TicketSyncContext(ctx context.Context, tenantID shared.ID, ids []shared.ID) context.Context
	// AfterStatusMoves runs the side effects of applied moves and returns
	// the proof-of-fix re-checks queued.
	AfterStatusMoves(ctx context.Context, tenantID shared.ID, actorID string, moves []vulnerability.StatusMove) int
}

var _ StatusEffects = (*VulnerabilityService)(nil)

// TicketSyncContext reads the findings (tenant-scoped) and puts the ticket
// status pushes of the linked ones on ctx (see StatusEffects).
func (s *VulnerabilityService) TicketSyncContext(ctx context.Context, tenantID shared.ID, ids []shared.ID) context.Context {
	if !s.ticketStatusSync || len(ids) == 0 {
		return ctx
	}
	if _, inbound := vulnerability.TicketInboundFrom(ctx); inbound {
		return ctx
	}
	found, err := s.findingRepo.GetByIDs(ctx, tenantID, ids)
	if err != nil {
		s.logger.Warn("ticket status sync: read findings", "error", err, "count", len(ids))
		return ctx
	}
	return s.ticketSyncCtx(ctx, tenantID, found)
}

// ticketSyncCtx puts the outbound ticket status pushes (Jira, GitHub
// Issues) of the linked findings on ctx, for the status write to queue in
// its transaction for each finding it moves. A move a ticket webhook makes
// is not pushed back to the ticket; unlinked findings queue nothing.
func (s *VulnerabilityService) ticketSyncCtx(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) context.Context {
	if !s.ticketStatusSync {
		return ctx
	}
	if _, inbound := vulnerability.TicketInboundFrom(ctx); inbound {
		return ctx
	}
	var jobs []durablejob.Job
	for _, f := range findings {
		if f != nil && len(f.WorkItemURIs()) > 0 {
			jobs = append(jobs, durablejob.StatusSyncJobs(tenantID, f.ID())...)
		}
	}
	return durablejob.WithEnqueue(ctx, jobs...)
}

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
// status change and fires nothing.
func (s *VulnerabilityService) afterStatusChange(ctx context.Context, tenantID shared.ID, actorID string, changes []statusChange) int {
	s.auditStatusChanges(ctx, tenantID, actorID, changes)
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
		// Only a change to one finding makes the actor a watcher: a bulk or
		// group move would subscribe them to every finding it touched.
		var watches participationdom.Reason
		if len(changes) == 1 {
			watches = participationdom.ReasonStatusChanged
			if newStatus == vulnerability.FindingStatusFixApplied {
				watches = participationdom.ReasonFixClaimed
			}
		}
		// A batch is told as one summary per person (below), not one notice
		// per finding.
		if len(changes) == 1 {
			s.notifyFinding(ctx, c.f, findingEvent{
				actorID: actorID,
				typ:     notification.TypeFindingStatusChange,
				title:   fmt.Sprintf("Finding status changed: %s → %s", c.old, newStatus),
				body:    c.f.Message(),
				// The feed hides status changes from pentest clients (they may
				// not see the old status the title names), so the notice does too.
				teamOnly:     isPentest(c.f),
				actorWatches: watches,
			})
		}
		if newStatus == vulnerability.FindingStatusFixApplied {
			fixClaims = append(fixClaims, c.f.ID())
		}
	}
	if len(changes) > 1 {
		s.notifyStatusBatch(ctx, actorID, changes)
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

// statusDigest is what one person is told about a batch of status moves.
type statusDigest struct {
	findings []*vulnerability.Finding
	statuses map[vulnerability.FindingStatus]struct{}
	reason   string
}

// notifyStatusBatch tells each person who would hear about any moved finding
// (assignee, watchers; membership, data scope and pentest visibility are
// re-checked per finding at send time) with one summary notice for the whole
// batch, not one per finding. The per-finding timeline and audit entries are
// written elsewhere and unchanged.
func (s *VulnerabilityService) notifyStatusBatch(ctx context.Context, actorID string, changes []statusChange) {
	if s.userNotificationService == nil {
		return
	}
	actor := person(actorID)
	digests := make(map[shared.ID]*statusDigest)
	var order []shared.ID
	add := func(uid shared.ID, c statusChange, reason string) {
		d := digests[uid]
		if d == nil {
			d = &statusDigest{statuses: map[vulnerability.FindingStatus]struct{}{}, reason: reason}
			digests[uid] = d
			order = append(order, uid)
		}
		d.findings = append(d.findings, c.f)
		d.statuses[c.new] = struct{}{}
	}
	for _, c := range changes {
		if c.old == c.new {
			continue
		}
		if s.participants == nil {
			if a := c.f.AssignedTo(); a != nil && (actor == nil || *a != *actor) {
				add(*a, c, notification.ReasonAssigned)
			}
			continue
		}
		pe := participation.Event{
			Item:     participationdom.Item{Kind: participationdom.ItemFinding, ID: c.f.ID()},
			Actor:    actor,
			TeamOnly: isPentest(c.f),
		}
		if a := c.f.AssignedTo(); a != nil {
			pe.Direct = []shared.ID{*a}
		}
		recipients, err := s.participants.Recipients(withLoadedFinding(ctx, c.f), c.f.TenantID(), pe)
		if err != nil {
			s.logger.Warn("status batch: recipients", "error", logger.SanitizeError(err))
			continue
		}
		for _, r := range recipients {
			add(r.UserID, c, r.Reason)
		}
	}
	for _, uid := range order {
		d := digests[uid]
		uid := uid
		title, url := statusDigestText(d)
		if err := s.userNotificationService.Notify(ctx, notification.NotificationParams{
			TenantID:         d.findings[0].TenantID(),
			Audience:         notification.AudienceUser,
			AudienceID:       &uid,
			NotificationType: notification.TypeFindingStatusChange,
			Severity:         highestSeverity(d.findings).String(),
			Title:            title,
			Body:             d.findings[0].Title(),
			ResourceType:     "finding",
			URL:              url,
			ActorID:          actor,
			Reason:           d.reason,
		}); err != nil {
			s.logger.Warn("status batch: notify", "error", logger.SanitizeError(err))
		}
	}
}

// statusDigestText words the summary and picks the list it links to: the
// moved status when the batch has one, else the person's work list.
func statusDigestText(d *statusDigest) (title, url string) {
	n := len(d.findings)
	if len(d.statuses) == 1 {
		for st := range d.statuses {
			return fmt.Sprintf("%d findings moved to %s", n, st), "/findings?status=" + st.String()
		}
	}
	return fmt.Sprintf("%d findings changed status", n), "/my-work"
}
