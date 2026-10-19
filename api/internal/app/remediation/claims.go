package remediation

// Claim conflicts: docs/rfcs/RFC-098-remediation-tasks.md §6.1.
//
// Before a request that adds primary members runs, prepareConflicts checks
// how the caller wants findings of other active tasks handled: a move needs
// remediation write access and write access to the source task (visible,
// with no finding outside the caller's scope), else 403. After a refusal,
// describeConflicts says what the caller may know about each holding task:
// its title and owner only when they can read it, and whether they may move
// the finding. After success, recordClaimMoves writes one audit row per
// source task and tells the trackers of both tasks.

import (
	"context"
	"errors"
	"fmt"
	"sort"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	remediationdom "github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// prepareConflicts validates a conflict resolution for the requested
// findings and, for a move, confirms the caller may change every task the
// moved findings are in now (target: the task the findings go to, when it
// exists). canWrite: the caller holds remediation write access.
func (s *TaskService) prepareConflicts(ctx context.Context, tenantID shared.ID, requested []shared.ID, res remediationdom.ConflictResolution, canWrite bool, target *shared.ID) (remediationdom.ConflictResolution, error) {
	res, err := res.Normalize(requested)
	if err != nil {
		return res, err
	}
	res.MovableFrom = nil
	if len(res.Move) == 0 {
		return res, nil
	}
	if !canWrite {
		return res, remediationdom.ErrMoveNotAllowed
	}
	current, err := s.repo.ActivePrimaryTasks(ctx, tenantID, res.Move)
	if err != nil {
		return res, err
	}
	res.MovableFrom = map[shared.ID]bool{}
	for _, taskID := range current {
		if res.MovableFrom[taskID] || (target != nil && taskID == *target) {
			continue
		}
		t, err := s.writableTask(ctx, tenantID, taskID)
		if err != nil {
			if errors.Is(err, shared.ErrNotFound) || errors.Is(err, shared.ErrForbidden) {
				return res, remediationdom.ErrMoveNotAllowed
			}
			return res, err
		}
		if t.State.IsTerminal() {
			return res, remediationdom.ErrTaskTerminal
		}
		res.MovableFrom[taskID] = true
	}
	return res, nil
}

// describeConflicts fills, for each conflict of a refusal, what the caller
// may know about the task that holds the finding. Other errors pass through.
func (s *TaskService) describeConflicts(ctx context.Context, tenantID shared.ID, err error, canWrite bool) error {
	e, ok := remediationdom.AsFindingsInOtherTask(err)
	if !ok {
		return err
	}
	conflicts := e.Conflicts
	if len(conflicts) == 0 && len(e.FindingIDs) > 0 {
		// A concurrent claim won at the insert: look the holders up.
		holders, herr := s.repo.ActivePrimaryTasks(ctx, tenantID, e.FindingIDs)
		if herr != nil {
			return herr
		}
		for _, id := range e.FindingIDs {
			if tid, ok := holders[id]; ok {
				conflicts = append(conflicts, remediationdom.FindingConflict{FindingID: id, TaskID: tid})
			}
		}
	}
	type view struct {
		task     *remediationdom.Task
		writable bool
	}
	seen := map[shared.ID]*view{}
	out := make([]remediationdom.FindingConflict, 0, len(conflicts))
	for _, c := range conflicts {
		v, ok := seen[c.TaskID]
		if !ok {
			v = &view{}
			t, gerr := s.GetTask(ctx, tenantID, c.TaskID)
			switch {
			case gerr == nil:
				v.task = t
				v.writable = canWrite && t.HiddenMembers == 0 && !t.State.IsTerminal()
			case errors.Is(gerr, shared.ErrNotFound):
				// Not readable: the caller learns only that it is taken.
			default:
				return gerr
			}
			seen[c.TaskID] = v
		}
		c.TaskTitle, c.AssigneeUserID, c.AssigneeGroupID, c.CanMove = nil, nil, nil, false
		if v.task != nil {
			title := v.task.Title
			c.TaskTitle = &title
			c.AssigneeUserID, c.AssigneeGroupID = v.task.AssigneeUserID, v.task.AssigneeGroupID
			c.CanMove = v.writable
		}
		out = append(out, c)
	}
	ids := make([]shared.ID, len(out))
	for i, c := range out {
		ids[i] = c.FindingID
	}
	return &remediationdom.FindingsInOtherTaskError{FindingIDs: ids, Conflicts: out}
}

// recordClaimMoves writes one audit row per source task of the moves and
// tells the trackers of both tasks of each move.
func (s *TaskService) recordClaimMoves(ctx context.Context, actx auditapp.AuditContext, tenantID shared.ID, rep remediationdom.ClaimReport, actor *shared.ID) {
	if len(rep.Moves) == 0 {
		return
	}
	bySource := map[shared.ID][]remediationdom.ClaimMove{}
	var order []shared.ID
	for _, m := range rep.Moves {
		if _, ok := bySource[m.FromTaskID]; !ok {
			order = append(order, m.FromTaskID)
		}
		bySource[m.FromTaskID] = append(bySource[m.FromTaskID], m)
	}
	sort.Slice(order, func(i, j int) bool { return order[i].String() < order[j].String() })
	for _, src := range order {
		moves := bySource[src]
		n, targets, archived := 0, make([]string, 0, len(moves)), false
		for _, m := range moves {
			n += len(m.FindingIDs)
			targets = append(targets, m.ToTaskID.String())
			archived = archived || m.SourceArchived
		}
		s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionRemediationTaskFindingsMoved, auditdom.ResourceTypeRemediationTask, src.String()).
			WithResourceName(moves[0].FromTitle).
			WithMessage(fmt.Sprintf("%d finding(s) moved out of %q into %q: %s", n, moves[0].FromTitle, moves[0].ToTitle, rep.Reason)).
			WithMetadata("findings", n).WithMetadata("to_task_ids", targets).WithMetadata("reason", rep.Reason).
			WithMetadata("archived_source", archived))
		for _, m := range moves {
			to := m.ToTaskID
			s.notifyMove(ctx, remediationdom.TaskMoveEvent{TenantID: tenantID, Kind: remediationdom.MoveKindMove, FromTaskID: m.FromTaskID,
				FromTitle: m.FromTitle, ToTaskID: &to, ToTitle: m.ToTitle, Findings: len(m.FindingIDs),
				SourceArchived: m.SourceArchived, ActorID: actor})
		}
	}
}
