package remediation

// Claim conflicts: docs/rfcs/RFC-098-remediation-tasks.md §6.1.
//
// A finding is the primary member of at most one active task. When findings
// are added to a task (accepting a suggestion, creating a task, adding
// members) and some already belong to another active task, the request is
// refused with a *FindingsInOtherTaskError unless it says how to resolve
// them: skip them, or move named ones (from tasks the caller may change).

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxMoveReason bounds the reason given for moving findings.
const MaxMoveReason = 500

// FindingConflict is one finding that already belongs to another active
// task. TaskTitle and the assignee are nil when the caller cannot read that
// task (they learn only that the finding is taken); CanMove reports whether
// the caller may change that task, and so move the finding out of it.
type FindingConflict struct {
	FindingID       shared.ID  `json:"finding_id"`
	FindingTitle    string     `json:"finding_title"`
	TaskID          shared.ID  `json:"task_id"`
	TaskTitle       *string    `json:"task_title"`
	AssigneeUserID  *shared.ID `json:"assignee_user_id"`
	AssigneeGroupID *shared.ID `json:"assignee_group_id"`
	CanMove         bool       `json:"can_move"`
}

// ConflictResolution says what to do with findings that belong to another
// active task. The zero value refuses them.
type ConflictResolution struct {
	// Skip leaves every taken finding out.
	Skip bool
	// Move takes these findings out of their current task into the new one;
	// other taken findings are skipped.
	Move []shared.ID
	// MoveReason is recorded on both tasks and in the audit log.
	MoveReason string
	// MovableFrom are the tasks the service confirmed the caller may change.
	// A move out of any other task is refused as a conflict (the finding
	// changed task since the check).
	MovableFrom map[shared.ID]bool
}

// Resolves reports whether the resolution handles taken findings at all.
func (r ConflictResolution) Resolves() bool { return r.Skip || len(r.Move) > 0 }

// Normalize checks the resolution against the findings of the request: the
// moved findings must be among them, and a move needs a reason.
func (r ConflictResolution) Normalize(requested []shared.ID) (ConflictResolution, error) {
	r.MoveReason = strings.TrimSpace(r.MoveReason)
	if len(r.Move) == 0 {
		r.Move, r.MoveReason = nil, ""
		return r, nil
	}
	in := make(map[shared.ID]bool, len(requested))
	for _, id := range requested {
		in[id] = true
	}
	seen := make(map[shared.ID]bool, len(r.Move))
	moves := make([]shared.ID, 0, len(r.Move))
	for _, id := range r.Move {
		if !in[id] {
			return r, fmt.Errorf("%w: a finding to move is not part of the request", shared.ErrValidation)
		}
		if !seen[id] {
			seen[id] = true
			moves = append(moves, id)
		}
	}
	if r.MoveReason == "" {
		return r, fmt.Errorf("%w: moving findings out of another task needs a reason", shared.ErrValidation)
	}
	if utf8.RuneCountInString(r.MoveReason) > MaxMoveReason {
		return r, fmt.Errorf("%w: the move reason is at most %d characters", shared.ErrValidation, MaxMoveReason)
	}
	r.Move = moves
	return r, nil
}

// ClaimMove is findings moved from one task into another while claiming.
type ClaimMove struct {
	FromTaskID     shared.ID
	FromTitle      string
	ToTaskID       shared.ID
	ToTitle        string
	FindingIDs     []shared.ID
	SourceArchived bool
}

// ClaimReport is how taken findings were resolved.
type ClaimReport struct {
	Skipped []shared.ID
	Moves   []ClaimMove
	Reason  string
}

// ErrMoveNotAllowed: the caller asked to move a finding out of a task they
// cannot change.
var ErrMoveNotAllowed = fmt.Errorf("%w: you cannot change the task that holds a finding to move; skip it or ask its owner", shared.ErrForbidden)

// ErrNoFindingLeft: every finding of the request closed or was skipped.
var ErrNoFindingLeft = fmt.Errorf("%w: no open finding is left to add (the others closed or were skipped)", shared.ErrValidation)
