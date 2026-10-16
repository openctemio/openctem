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
