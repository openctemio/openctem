package remediation

// Group-level exception on a remediation task
// (api/docs/rfcs/RFC-111-approval-policy.md §7): "no maintenance window until
// 1 December" is one request about the task's open findings, decided once by
// the approval policy (the finding service owns the request and its
// decision). Every finding of the task must be in the caller's scope, as for
// any change of the task.

import (
	"context"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/finding"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	remediationdom "github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// TaskExceptionRequester previews and creates group exceptions
// (*finding.VulnerabilityService).
type TaskExceptionRequester interface {
	PreviewGroupException(ctx context.Context, in finding.GroupExceptionInput) (*finding.GroupExceptionPreview, error)
	RequestGroupException(ctx context.Context, in finding.GroupExceptionInput) (*finding.GroupExceptionResult, error)
}

// SetExceptionRequester wires group exceptions. Without it they are refused.
func (s *TaskService) SetExceptionRequester(r TaskExceptionRequester) { s.exceptions = r }

// ErrExceptionUnavailable: group exceptions are not wired.
var ErrExceptionUnavailable = fmt.Errorf("%w: exceptions on tasks are not available", shared.ErrValidation)

// TaskExceptionInput asks for an exception on a task's open findings.
type TaskExceptionInput struct {
	TenantID        shared.ID
	TaskID          shared.ID
	RequestedStatus string
	ClosureReason   string
	Justification   string
	ExpiresAt       *time.Time
	ActorID         shared.ID
	// Approved lets an over-ceiling group through the bulk abuse guard.
	Approved bool
}

func (s *TaskService) exceptionInput(ctx context.Context, in TaskExceptionInput) (finding.GroupExceptionInput, *remediationdom.Task, error) {
	if s.exceptions == nil {
		return finding.GroupExceptionInput{}, nil, ErrExceptionUnavailable
	}
	t, err := s.writableTask(ctx, in.TenantID, in.TaskID)
	if err != nil {
		return finding.GroupExceptionInput{}, nil, err
	}
	if t.State.IsTerminal() {
		return finding.GroupExceptionInput{}, nil, remediationdom.ErrTaskTerminal
	}
	ids, err := s.repo.OpenPrimaryIDs(ctx, in.TenantID, in.TaskID)
	if err != nil {
		return finding.GroupExceptionInput{}, nil, err
	}
	return finding.GroupExceptionInput{
		TenantID: in.TenantID, SourceType: vulnerability.ApprovalBatchSourceTask, SourceID: in.TaskID, FindingIDs: ids,
		RequestedStatus: in.RequestedStatus, ClosureReason: in.ClosureReason, Justification: in.Justification,
		ExpiresAt: in.ExpiresAt, RequestedBy: in.ActorID,
	}, t, nil
}

// PreviewException answers how an exception on the task would be decided.
func (s *TaskService) PreviewException(ctx context.Context, in TaskExceptionInput) (*finding.GroupExceptionPreview, error) {
	gi, _, err := s.exceptionInput(ctx, in)
	if err != nil {
		return nil, err
	}
	return s.exceptions.PreviewGroupException(ctx, gi)
}

// RequestException creates the exception request on the task's open
// findings (one decision; each finding then carries its own end).
func (s *TaskService) RequestException(ctx context.Context, in TaskExceptionInput, actx auditapp.AuditContext) (*finding.GroupExceptionResult, error) {
	gi, t, err := s.exceptionInput(ctx, in)
	if err != nil {
		return nil, err
	}
	if s.guard != nil {
		if err := s.guard.CheckBulk(ctx, in.TenantID, len(gi.FindingIDs), in.Approved); err != nil {
			return nil, err
		}
	}
	res, err := s.exceptions.RequestGroupException(ctx, gi)
	if err != nil {
		return nil, err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionRemediationTaskExceptionRequested, auditdom.ResourceTypeRemediationTask, t.ID.String()).
		WithResourceName(t.Title).
		WithMessage(fmt.Sprintf("Exception requested on remediation task %q: %s for %d finding(s), tier %s",
			t.Title, in.RequestedStatus, res.Batch.MemberCount, res.Batch.Tier)).
		WithMetadata("batch_id", res.Batch.ID.String()).
		WithMetadata("requested_status", in.RequestedStatus).
		WithMetadata("members", res.Batch.MemberCount).
		WithMetadata("tier", res.Batch.Tier))
	return res, nil
}
