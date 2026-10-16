package remediation

// Moving findings between remediation tasks, splitting and merging tasks:
// docs/rfcs/RFC-098-remediation-tasks.md §7.
//
// Refused: another tenant (not found), a closed, canceled or archived task,
// a task with findings outside the caller's scope, findings outside it.
// Confirmed by the person: a different fix, a different owner, a task in
// verification, emptying the source. Every request names the versions of
// the tasks it read, so a concurrent change answers 409.

import (
	"context"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	remediationdom "github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MoveInput moves findings; ToTaskID nil takes them out of any task.
type MoveInput struct {
	TenantID    shared.ID
	FromTaskID  shared.ID
	FromVersion int
	ToTaskID    *shared.ID
	ToVersion   int
	FindingIDs  []shared.ID
	// Confirm accepts the warnings of the move.
	Confirm bool
	ActorID *shared.ID
}

// MovePreview is what a move would do, before it is done.
type MovePreview struct {
	Warnings []remediationdom.MoveWarning `json:"warnings"`
	Moving   int                          `json:"moving"`
}

// MoveOutcome is what a move did, with both tasks after it.
type MoveOutcome struct {
	Moved          []shared.ID
	Skipped        []shared.ID
	SourceArchived bool
	Source         *remediationdom.Task
	Target         *remediationdom.Task
	Warnings       []remediationdom.MoveWarning
}

func (s *TaskService) moveTasks(ctx context.Context, in MoveInput) (*remediationdom.Task, *remediationdom.Task, error) {
	if in.FromVersion <= 0 || (in.ToTaskID != nil && in.ToVersion <= 0) {
		return nil, nil, ErrTaskVersionRequired
	}
	ids := dedupeIDs(in.FindingIDs)
	if len(ids) == 0 {
		return nil, nil, ErrTaskNoFindings
	}
	if len(ids) > remediationdom.MaxMembersPerRequest {
		return nil, nil, ErrTaskTooManyFindings
	}
	src, err := s.writableTask(ctx, in.TenantID, in.FromTaskID)
	if err != nil {
		return nil, nil, err
	}
	if src.State.IsTerminal() {
		return nil, nil, remediationdom.ErrTaskTerminal
	}
	var dst *remediationdom.Task
	if in.ToTaskID != nil {
		if dst, err = s.writableTask(ctx, in.TenantID, *in.ToTaskID); err != nil {
			return nil, nil, err
		}
		if dst.State.IsTerminal() {
			return nil, nil, remediationdom.ErrTaskTerminal
		}
	}
	// Every finding named must be in the caller's scope (and the tenant).
	if err := s.checkFindings(ctx, in.TenantID, ids, nil); err != nil {
		return nil, nil, err
	}
	return src, dst, nil
}

// PreviewMove returns the warnings of a move without doing it.
func (s *TaskService) PreviewMove(ctx context.Context, in MoveInput) (*MovePreview, error) {
	src, dst, err := s.moveTasks(ctx, in)
	if err != nil {
		return nil, err
	}
	n, err := s.repo.CountActivePrimary(ctx, in.TenantID, src.ID, dedupeIDs(in.FindingIDs))
	if err != nil {
		return nil, err
	}
	w := remediationdom.MoveWarnings(src, dst, n)
	if w == nil {
		w = []remediationdom.MoveWarning{}
	}
	return &MovePreview{Warnings: w, Moving: n}, nil
}

// Move moves findings between tasks (or out of any task).
func (s *TaskService) Move(ctx context.Context, in MoveInput, actx auditapp.AuditContext) (*MoveOutcome, error) {
	src, dst, err := s.moveTasks(ctx, in)
	if err != nil {
		return nil, err
	}
	ids := dedupeIDs(in.FindingIDs)
	n, err := s.repo.CountActivePrimary(ctx, in.TenantID, src.ID, ids)
	if err != nil {
		return nil, err
	}
	warnings := remediationdom.MoveWarnings(src, dst, n)
	if len(warnings) > 0 && !in.Confirm {
		return nil, &remediationdom.MoveNeedsConfirmationError{Warnings: warnings}
	}
	req := remediationdom.MoveRequest{TenantID: in.TenantID, FromTaskID: src.ID, FromVersion: in.FromVersion,
		ToTaskID: in.ToTaskID, ToVersion: in.ToVersion, FindingIDs: ids, ActorID: in.ActorID}
	if dst == nil {
		req.Reason = remediationdom.LeftReasonDetached
		if src.ActionKind != remediationdom.ActionKindManual {
			req.ExcludeKey = src.ActionKey
		}
	}
	res, err := s.repo.MoveMembers(ctx, req)
	if err != nil {
		return nil, err
	}
	out := &MoveOutcome{Moved: res.Moved, Skipped: res.Skipped, SourceArchived: res.SourceArchived, Warnings: warnings}
	if out.Source, err = s.repo.GetTask(ctx, in.TenantID, src.ID); err != nil {
		return nil, err
	}
	target := ""
	if dst != nil {
		if out.Target, err = s.repo.GetTask(ctx, in.TenantID, dst.ID); err != nil {
			return nil, err
		}
		target = dst.Title
	}
	msg := fmt.Sprintf("%d finding(s) moved from %q to %q", len(res.Moved), src.Title, target)
	if dst == nil {
		msg = fmt.Sprintf("%d finding(s) taken out of %q", len(res.Moved), src.Title)
	}
	ev := auditapp.NewSuccessEvent(auditdom.ActionRemediationTaskMembersMoved, auditdom.ResourceTypeRemediationTask, src.ID.String()).
		WithResourceName(src.Title).WithMessage(msg).WithMetadata("findings", len(res.Moved)).
		WithMetadata("archived_source", res.SourceArchived)
	if dst != nil {
		ev = ev.WithMetadata("to_task_id", dst.ID.String())
	}
	if len(warnings) > 0 {
		ws := make([]string, len(warnings))
		for i, w := range warnings {
			ws[i] = string(w)
		}
		ev = ev.WithMetadata("confirmed_warnings", ws).WithSeverity(auditdom.SeverityMedium)
	}
	s.logAudit(ctx, actx, ev)
	return out, nil
}

// SplitInput splits findings off a task into a new task of the same fix.
type SplitInput struct {
	TenantID        shared.ID
	TaskID          shared.ID
	Version         int
	FindingIDs      []shared.ID
	Title           string
	AssigneeUserID  *shared.ID
	AssigneeGroupID *shared.ID
	ActorID         *shared.ID
}

// Split creates a task of the same fix from some of a task's findings and
// moves them there. The new task keeps the owner unless another is named.
func (s *TaskService) Split(ctx context.Context, in SplitInput, actx auditapp.AuditContext) (*MoveOutcome, error) {
	src, err := s.writableTask(ctx, in.TenantID, in.TaskID)
	if err != nil {
		return nil, err
	}
	if src.State.IsTerminal() {
		return nil, remediationdom.ErrTaskTerminal
	}
	ids := dedupeIDs(in.FindingIDs)
	if len(ids) == 0 {
		return nil, ErrTaskNoFindings
	}
	if len(ids) >= src.Counts.Total {
		return nil, fmt.Errorf("%w: a split leaves at least one finding in the task", shared.ErrValidation)
	}
	title := src.Title
	if in.Title != "" {
		if title, err = remediationdom.NormalizeTaskTitle(in.Title); err != nil {
			return nil, err
		}
	}
	owner := remediationdom.Owner{UserID: src.AssigneeUserID, GroupID: src.AssigneeGroupID}
	if in.AssigneeUserID != nil || in.AssigneeGroupID != nil {
		owner = remediationdom.Owner{UserID: in.AssigneeUserID, GroupID: in.AssigneeGroupID}
		if err := s.checkOwner(ctx, in.TenantID, owner.UserID, owner.GroupID); err != nil {
			return nil, err
		}
	}
	if err := s.checkFindings(ctx, in.TenantID, ids, nil); err != nil {
		return nil, err
	}
	childID, res, err := s.repo.SplitTask(ctx, remediationdom.SplitRequest{TenantID: in.TenantID, TaskID: src.ID, Version: in.Version,
		FindingIDs: ids, Title: title, Owner: owner, ActorID: in.ActorID})
	if err != nil {
		return nil, err
	}
	out := &MoveOutcome{Moved: res.Moved, Skipped: res.Skipped}
	if out.Source, err = s.repo.GetTask(ctx, in.TenantID, src.ID); err != nil {
		return nil, err
	}
	if out.Target, err = s.repo.GetTask(ctx, in.TenantID, childID); err != nil {
		return nil, err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionRemediationTaskSplit, auditdom.ResourceTypeRemediationTask, src.ID.String()).
		WithResourceName(src.Title).WithMessage(fmt.Sprintf("%d finding(s) of %q split into a new task %q", len(res.Moved), src.Title, title)).
		WithMetadata("new_task_id", childID.String()).WithMetadata("findings", len(res.Moved)))
	return out, nil
}

// MergeInput merges tasks of the same fix into a target.
type MergeInput struct {
	TenantID      shared.ID
	TargetID      shared.ID
	TargetVersion int
	Sources       map[shared.ID]int
	ActorID       *shared.ID
}

// Merge moves every finding of the source tasks (same fix only) into the
// target; the sources are archived with a note.
func (s *TaskService) Merge(ctx context.Context, in MergeInput, actx auditapp.AuditContext) (*remediationdom.Task, error) {
	if in.TargetVersion <= 0 || len(in.Sources) == 0 {
		return nil, fmt.Errorf("%w: a target version and at least one source task are required", shared.ErrValidation)
	}
	if len(in.Sources) > 20 {
		return nil, fmt.Errorf("%w: at most 20 tasks at once", shared.ErrValidation)
	}
	target, err := s.writableTask(ctx, in.TenantID, in.TargetID)
	if err != nil {
		return nil, err
	}
	if target.State.IsTerminal() {
		return nil, remediationdom.ErrTaskTerminal
	}
	for id, v := range in.Sources {
		if id == in.TargetID || v <= 0 {
			return nil, fmt.Errorf("%w: a source must be another task, with its version", shared.ErrValidation)
		}
		src, err := s.writableTask(ctx, in.TenantID, id)
		if err != nil {
			return nil, err
		}
		if src.State.IsTerminal() {
			return nil, remediationdom.ErrTaskTerminal
		}
		if src.ActionID != target.ActionID {
			return nil, remediationdom.ErrMergeDifferentFix
		}
	}
	n, err := s.repo.MergeTasks(ctx, remediationdom.MergeRequest{TenantID: in.TenantID, TargetID: in.TargetID,
		TargetVersion: in.TargetVersion, Sources: in.Sources, ActorID: in.ActorID})
	if err != nil {
		return nil, err
	}
	t, err := s.repo.GetTask(ctx, in.TenantID, in.TargetID)
	if err != nil {
		return nil, err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionRemediationTaskMerged, auditdom.ResourceTypeRemediationTask, t.ID.String()).
		WithResourceName(t.Title).WithMessage(fmt.Sprintf("%d task(s) merged into %q (%d finding(s))", len(in.Sources), t.Title, n)).
		WithMetadata("sources", len(in.Sources)).WithMetadata("findings", n))
	return t, nil
}
