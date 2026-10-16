package remediation

// Moves, splits and merges: docs/rfcs/RFC-098-remediation-tasks.md §7.

import (
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MoveRequest moves findings from one task to another task, or out of any
// task (ToTaskID nil: detach).
type MoveRequest struct {
	TenantID    shared.ID
	FromTaskID  shared.ID
	FromVersion int
	ToTaskID    *shared.ID
	ToVersion   int
	FindingIDs  []shared.ID
	// Reason is moved (default), split or merged.
	Reason LeftReason
	// ExcludeKey: on detach, the key the findings are no longer proposed
	// for.
	ExcludeKey string
	ActorID    *shared.ID
}

// MoveResult is what a move did.
type MoveResult struct {
	Moved          []shared.ID
	Skipped        []shared.ID
	SourceArchived bool
}

// MoveWarning is a reason a move needs the person's confirmation.
type MoveWarning string

const (
	// MoveWarnDifferentFix: the target fixes something else.
	MoveWarnDifferentFix MoveWarning = "different_fix"
	// MoveWarnDifferentOwner: the move hands the findings to another owner.
	MoveWarnDifferentOwner MoveWarning = "different_owner"
	// MoveWarnTargetVerifying: the target is waiting for verification.
	MoveWarnTargetVerifying MoveWarning = "target_verifying"
	// MoveWarnSourceVerifying: findings leave a task in verification (their
	// own checks continue).
	MoveWarnSourceVerifying MoveWarning = "source_verifying"
	// MoveWarnEmptiesSource: the source loses its last finding and is
	// archived.
	MoveWarnEmptiesSource MoveWarning = "empties_source"
)

// MoveWarnings lists what a person must confirm before moving findings from
// one task to another (target nil: taking them out of any task). The
// refusals (another tenant, a closed task, findings out of scope) are not
// warnings: they are errors.
func MoveWarnings(src, dst *Task, moving int) []MoveWarning {
	var w []MoveWarning
	if dst != nil {
		if dst.ActionID != src.ActionID {
			w = append(w, MoveWarnDifferentFix)
		}
		if ownerKey(dst) != ownerKey(src) {
			w = append(w, MoveWarnDifferentOwner)
		}
		if dst.State == TaskStateVerifying {
			w = append(w, MoveWarnTargetVerifying)
		}
	}
	if src.State == TaskStateVerifying {
		w = append(w, MoveWarnSourceVerifying)
	}
	if moving >= src.Counts.Total {
		w = append(w, MoveWarnEmptiesSource)
	}
	return w
}

func ownerKey(t *Task) string {
	return Owner{UserID: t.AssigneeUserID, GroupID: t.AssigneeGroupID}.Key()
}

// MoveNeedsConfirmationError carries the warnings a person must confirm.
type MoveNeedsConfirmationError struct {
	Warnings []MoveWarning
}

func (e *MoveNeedsConfirmationError) Error() string {
	return "the move needs confirmation"
}

// Unwrap makes the error a conflict.
func (e *MoveNeedsConfirmationError) Unwrap() error { return shared.ErrConflict }

// ErrMergeDifferentFix: only tasks of the same action merge.
var ErrMergeDifferentFix = fmt.Errorf("%w: only tasks of the same fix can be merged; move the findings instead", shared.ErrValidation)

// SplitRequest splits findings off a task into a new task of the same fix.
type SplitRequest struct {
	TenantID   shared.ID
	TaskID     shared.ID
	Version    int
	FindingIDs []shared.ID
	Title      string
	Owner      Owner
	ActorID    *shared.ID
}

// MergeRequest merges tasks of one fix into a target task.
type MergeRequest struct {
	TenantID      shared.ID
	TargetID      shared.ID
	TargetVersion int
	// Sources maps each source task to the version the caller read.
	Sources map[shared.ID]int
	ActorID *shared.ID
}

// MoveKind names what moved findings between tasks.
type MoveKind string

const (
	MoveKindMove   MoveKind = "move"
	MoveKindDetach MoveKind = "detach"
	MoveKindSplit  MoveKind = "split"
	MoveKindMerge  MoveKind = "merge"
)

// TaskMoveEvent is one stored move of findings out of a task (into another
// task, a new split task, a merge target, or out of any task).
type TaskMoveEvent struct {
	TenantID       shared.ID
	Kind           MoveKind
	FromTaskID     shared.ID
	FromTitle      string
	ToTaskID       *shared.ID
	ToTitle        string
	Findings       int
	SourceArchived bool
	ActorID        *shared.ID
}

// TaskComment is a comment for the tracker issue of one task.
type TaskComment struct {
	TaskID shared.ID
	Body   string
}

// Comments returns the comment for each task the move touched: the source
// and, when there is one, the target. They carry counts and task titles
// only, never finding identifiers or titles: people who see the issue may
// not see every finding.
func (e TaskMoveEvent) Comments() []TaskComment {
	if e.Findings <= 0 {
		return nil
	}
	n := fmt.Sprintf("%d finding", e.Findings)
	if e.Findings != 1 {
		n += "s"
	}
	var src string
	switch {
	case e.ToTaskID == nil:
		src = fmt.Sprintf("%s taken out of this task.", n)
	case e.Kind == MoveKindSplit:
		src = fmt.Sprintf("%s split off into a new task %q.", n, e.ToTitle)
	case e.Kind == MoveKindMerge:
		src = fmt.Sprintf("This task was merged into %q (%s).", e.ToTitle, n)
	default:
		src = fmt.Sprintf("%s moved to task %q.", n, e.ToTitle)
	}
	if e.SourceArchived && e.Kind != MoveKindMerge {
		src += " The task has no findings left and is archived."
	}
	out := []TaskComment{{TaskID: e.FromTaskID, Body: src}}
	if e.ToTaskID != nil {
		dst := fmt.Sprintf("%s moved in from task %q.", n, e.FromTitle)
		switch e.Kind {
		case MoveKindSplit:
			dst = fmt.Sprintf("Created from %s split off task %q.", n, e.FromTitle)
		case MoveKindMerge:
			dst = fmt.Sprintf("Task %q was merged into this one (%s).", e.FromTitle, n)
		}
		out = append(out, TaskComment{TaskID: *e.ToTaskID, Body: dst})
	}
	return out
}
