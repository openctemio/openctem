package remediation

// Telling the trackers about moves: docs/rfcs/RFC-098-remediation-tasks.md §7
// and §9. After a move, split or merge is stored, each task it touched gets a
// comment on its tracker issue (counts and task titles only). The ticket
// integration implements TaskMoveNotifier; the call is best effort and never
// fails or undoes the move.

import (
	"context"

	remediationdom "github.com/openctemio/openctem/api/pkg/domain/remediation"
)

// TaskMoveNotifier hears about stored moves. Implementations must not block
// the request for long: post or queue the comments of ev.Comments() for the
// tasks that carry an issue, and log their own failures.
type TaskMoveNotifier interface {
	TaskMembersMoved(ctx context.Context, ev remediationdom.TaskMoveEvent)
}

// SetMoveNotifier wires the tracker comments on moves.
func (s *TaskService) SetMoveNotifier(n TaskMoveNotifier) { s.moves = n }

func (s *TaskService) notifyMove(ctx context.Context, ev remediationdom.TaskMoveEvent) {
	if s.moves == nil || ev.Findings <= 0 {
		return
	}
	s.moves.TaskMembersMoved(ctx, ev)
}
