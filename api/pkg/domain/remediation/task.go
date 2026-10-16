package remediation

// Remediation actions and tasks: docs/rfcs/RFC-098-remediation-tasks.md.
//
// An Action is what fixes a set of findings; a Task is who does that fix and
// by when. A task's state, deadline and counters are derived from its member
// findings; a person sets only the owner, a tighter deadline, the title and
// the two manual states (on hold, canceled).

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TaskState is the state of a remediation task.
type TaskState string

const (
	// TaskStateOpen: no member is being worked on yet.
	TaskStateOpen TaskState = "open"
	// TaskStateInProgress: some members are in progress or claimed fixed.
	TaskStateInProgress TaskState = "in_progress"
	// TaskStateVerifying: every open member is claimed fixed and awaits its
	// own verification.
	TaskStateVerifying TaskState = "verifying"
	// TaskStateDone: every member is closed and at least one was verified
	// fixed.
	TaskStateDone TaskState = "done"
	// TaskStateClosedUnverified: every member is closed but none was
	// verified fixed (all accepted, false positive or duplicate, or resolved
	// without proof). Not done: nothing was shown to be fixed.
	TaskStateClosedUnverified TaskState = "closed_unverified"
	// TaskStateOnHold and TaskStateCanceled are set by a person.
	TaskStateOnHold   TaskState = "on_hold"
	TaskStateCanceled TaskState = "canceled"
	// TaskStateArchived: the task lost its last member to a move.
	TaskStateArchived TaskState = "archived"
)

// AllTaskStates lists every task state.
func AllTaskStates() []TaskState {
	return []TaskState{
		TaskStateOpen, TaskStateInProgress, TaskStateVerifying, TaskStateDone,
		TaskStateClosedUnverified, TaskStateOnHold, TaskStateCanceled, TaskStateArchived,
	}
}

// IsValid reports whether s is a known task state.
func (s TaskState) IsValid() bool {
	for _, v := range AllTaskStates() {
		if s == v {
			return true
		}
	}
	return false
}

// IsTerminal reports whether a task in this state takes no new members and
// no edits: canceled, archived, done or closed without verification. A
// regression of a done task opens a new task instead of reopening it.
func (s TaskState) IsTerminal() bool {
	switch s {
	case TaskStateCanceled, TaskStateArchived, TaskStateDone, TaskStateClosedUnverified:
		return true
	}
	return false
}

// ManualState is a state a person sets on a task.
type ManualState string

const (
	ManualStateOnHold   ManualState = "on_hold"
	ManualStateCanceled ManualState = "canceled"
)

// DeadlineSource names what set a task's effective deadline.
type DeadlineSource string

const (
	DeadlineSourceMember   DeadlineSource = "member"
	DeadlineSourceManual   DeadlineSource = "manual"
	DeadlineSourceCampaign DeadlineSource = "campaign"
)

// MemberRole is how a finding belongs to a task.
type MemberRole string

const (
	// MemberRolePrimary: the task that fixes the finding. A finding is the
	// primary member of at most one active task.
	MemberRolePrimary MemberRole = "primary"
	// MemberRoleRelated: "also fixed by" — no state, no deadline, no ticket
	// effect.
	MemberRoleRelated MemberRole = "related"
)

// JoinSource is how a member joined a task.
type JoinSource string

const (
	JoinSourceManual     JoinSource = "manual"
	JoinSourceSuggestion JoinSource = "suggestion"
	JoinSourceAutoJoin   JoinSource = "auto_join"
	JoinSourceMove       JoinSource = "move"
	JoinSourceSplit      JoinSource = "split"
	JoinSourceMerge      JoinSource = "merge"
	JoinSourceRegression JoinSource = "regression"
)

// LeftReason is why a member left a task.
type LeftReason string

const (
	LeftReasonRemoved   LeftReason = "removed"
	LeftReasonMoved     LeftReason = "moved"
	LeftReasonSplit     LeftReason = "split"
	LeftReasonMerged    LeftReason = "merged"
	LeftReasonRegressed LeftReason = "regressed"
	LeftReasonDetached  LeftReason = "detached"
	// LeftReasonCanceled: the task was canceled; its findings are free to
	// join another task.
	LeftReasonCanceled LeftReason = "canceled"
)

// ActionKindManual is the kind of an action a person named by hand.
const ActionKindManual = "manual"

// ActionOrigin is how an action came to exist: always by a person, either by
// hand or by accepting a suggestion.
type ActionOrigin string

const (
	ActionOriginManual     ActionOrigin = "manual"
	ActionOriginSuggestion ActionOrigin = "suggestion"
)

// Limits.
const (
	MaxTaskTitle       = 300
	MaxTaskDescription = 10000
	MaxStateNote       = 500
	// MaxMembersPerRequest bounds one add/create request.
	MaxMembersPerRequest = 500
)

// Action is what fixes a set of findings.
type Action struct {
	ID        shared.ID
	TenantID  shared.ID
	Key       string
	Kind      string
	Title     string
	FixSpec   map[string]any
	Origin    ActionOrigin
	CreatedBy *shared.ID
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ManualActionKey is the key of an action a person named by hand for one
// task: unique, so two hand-made tasks never share an action by accident.
func ManualActionKey(taskID shared.ID) string {
	return ActionKindManual + ":" + taskID.String()
}

// TaskCounts are the member counters a task's state is derived from. Every
// counter is over active primary members, except Related.
type TaskCounts struct {
	Total      int
	Open       int // new, confirmed, not observed, draft, in review
	InProgress int // in_progress
	FixApplied int // fix_applied, validated_fixed: claimed fixed, awaiting verification
	Closed     int // resolved, false_positive, accepted, duplicate
	Verified   int // resolved with proof (a covered scan, a retest or a reviewer)
	Related    int
	RiskPoints int
	// MemberDeadline is the earliest SLA deadline of an open member.
	MemberDeadline *time.Time
}

// DeriveState computes a task's state from the manual state, the archive
// mark and the member counters. The rules, first match wins:
//
//	archived → canceled → on hold (manual)
//	no member → open
//	every member closed → done when at least one is verified fixed,
//	                      else closed_unverified
//	every open member claimed fixed → verifying
//	any member in progress or claimed fixed → in_progress
//	otherwise → open
func DeriveState(manual *ManualState, archived bool, c TaskCounts) TaskState {
	switch {
	case archived:
		return TaskStateArchived
	case manual != nil && *manual == ManualStateCanceled:
		return TaskStateCanceled
	case manual != nil && *manual == ManualStateOnHold:
		return TaskStateOnHold
	case c.Total == 0:
		return TaskStateOpen
	case c.Closed >= c.Total:
		if c.Verified > 0 {
			return TaskStateDone
		}
		return TaskStateClosedUnverified
	case c.FixApplied > 0 && c.FixApplied >= c.Total-c.Closed:
		return TaskStateVerifying
	case c.InProgress+c.FixApplied > 0:
		return TaskStateInProgress
	}
	return TaskStateOpen
}

// EffectiveDeadline is the earliest of the open members' SLA deadline, a
// person's deadline and the campaign's deadline. Taking the minimum is what
// makes a manual or campaign deadline tighten only: neither can move a
// member's own deadline later.
func EffectiveDeadline(member, manual, campaign *time.Time) (*time.Time, *DeadlineSource) {
	var (
		best *time.Time
		src  DeadlineSource
	)
	consider := func(t *time.Time, s DeadlineSource) {
		if t == nil {
			return
		}
		if best == nil || t.Before(*best) {
			v := *t
			best, src = &v, s
		}
	}
	consider(member, DeadlineSourceMember)
	consider(manual, DeadlineSourceManual)
	consider(campaign, DeadlineSourceCampaign)
	if best == nil {
		return nil, nil
	}
	return best, &src
}

// Task is who fixes an action and by when.
type Task struct {
	ID              shared.ID
	TenantID        shared.ID
	ActionID        shared.ID
	ActionKey       string
	ActionKind      string
	ActionTitle     string
	CampaignID      *shared.ID
	Title           string
	Description     string
	AssigneeUserID  *shared.ID
	AssigneeGroupID *shared.ID
	ManualState     *ManualState
	ManualStateNote string
	State           TaskState
	Deadline        *time.Time
	DeadlineSource  *DeadlineSource
	ManualDeadline  *time.Time
	Counts          TaskCounts
	RegressionOf    *shared.ID
	ArchivedAt      *time.Time
	ArchivedNote    string
	ClosedAt        *time.Time
	Version         int
	CreatedBy       *shared.ID
	CreatedAt       time.Time
	UpdatedAt       time.Time

	// HiddenMembers is the number of active primary members outside the
	// caller's data scope (set per request, never stored). The counters
	// above are then over the visible members only.
	HiddenMembers int
}

// TaskMember is one finding of a task, with what a member table shows.
type TaskMember struct {
	FindingID     shared.ID
	Role          MemberRole
	JoinSource    JoinSource
	JoinedAt      time.Time
	JoinedBy      *shared.ID
	Title         string
	Severity      string
	Status        string
	PriorityClass string
	AssetID       *shared.ID
	AssetName     string
	SLADeadline   *time.Time
	Verified      bool
}

// TaskEvent is one entry of a task's timeline.
type TaskEvent struct {
	ID        shared.ID
	TaskID    shared.ID
	Kind      string
	ActorID   *shared.ID
	ActorType string
	Data      map[string]any
	CreatedAt time.Time
}

// Task event kinds.
const (
	TaskEventCreated        = "created"
	TaskEventMembersAdded   = "members_added"
	TaskEventMembersRemoved = "members_removed"
	TaskEventUpdated        = "updated"
	TaskEventStateChanged   = "state_changed"
)

// Errors.
var (
	ErrTaskNotFound = fmt.Errorf("%w: remediation task not found", shared.ErrNotFound)
	// ErrTaskVersionConflict: the task changed since the caller read it.
	ErrTaskVersionConflict = fmt.Errorf("%w: the task was changed by someone else; reload it and try again", shared.ErrConflict)
	// ErrTaskTerminal: a canceled, archived or closed task takes no edits
	// and no new members.
	ErrTaskTerminal = fmt.Errorf("%w: the task is closed, canceled or archived", shared.ErrValidation)
	// ErrTaskHiddenMembers: a restricted caller may not change a task that
	// has members outside their data scope.
	ErrTaskHiddenMembers = fmt.Errorf("%w: the task has findings outside your access; ask someone who can see all of them", shared.ErrForbidden)
)

// FindingsInOtherTaskError lists findings that are already the primary
// member of another active task (a finding has one primary task).
type FindingsInOtherTaskError struct {
	FindingIDs []shared.ID
}

func (e *FindingsInOtherTaskError) Error() string {
	return fmt.Sprintf("%d finding(s) already belong to another remediation task; move them instead", len(e.FindingIDs))
}

// Unwrap makes the error a conflict.
func (e *FindingsInOtherTaskError) Unwrap() error { return shared.ErrConflict }

// AsFindingsInOtherTask unwraps a FindingsInOtherTaskError.
func AsFindingsInOtherTask(err error) (*FindingsInOtherTaskError, bool) {
	var e *FindingsInOtherTaskError
	ok := errors.As(err, &e)
	return e, ok
}

// NormalizeTaskTitle trims a title and checks its length.
func NormalizeTaskTitle(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("%w: title is required", shared.ErrValidation)
	}
	if len(s) > MaxTaskTitle {
		return "", fmt.Errorf("%w: title is longer than %d characters", shared.ErrValidation, MaxTaskTitle)
	}
	return s, nil
}

// TaskSort orders a task list.
type TaskSort string

const (
	TaskSortDeadline TaskSort = "deadline" // earliest first, no deadline last
	TaskSortRisk     TaskSort = "risk"     // most risk left first
	TaskSortUpdated  TaskSort = "updated"  // most recently changed first
	TaskSortCreated  TaskSort = "created"  // newest first
)

// IsValid reports whether s is a known sort.
func (s TaskSort) IsValid() bool {
	switch s {
	case TaskSortDeadline, TaskSortRisk, TaskSortUpdated, TaskSortCreated:
		return true
	}
	return false
}

// TaskFilter narrows a task list. Every field is optional.
type TaskFilter struct {
	States     []TaskState
	AssigneeID *shared.ID // the user, or any of their groups when Mine
	Mine       bool       // assigned to AssigneeID or to one of their groups
	GroupID    *shared.ID
	ActionID   *shared.ID
	ActionKind string
	CampaignID *shared.ID
	FindingID  *shared.ID // tasks the finding is an active member of
	Search     string
	Sort       TaskSort
	// Scope limits the list to tasks with at least one active primary
	// member in the caller's data scope (nil = unrestricted).
	Scope *shared.DataScope
}
