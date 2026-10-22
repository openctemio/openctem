package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// assertCommentNotDecisionLocked refuses a change to a comment written by a
// participant of an approval request while that request was open or after it
// was decided. Such a comment is the justification beside a false-positive,
// acceptance decision and must not be rewritten or removed. A request that
// was canceled decided nothing and locks nothing; an accepted risk whose
// period ended (expired) was decided and stays locked.
func (s *VulnerabilityService) assertCommentNotDecisionLocked(ctx context.Context, tenantID shared.ID, comment *vulnerability.FindingComment) error {
	if s.approvalRepo == nil {
		return nil
	}
	approvals, err := s.approvalRepo.ListByFinding(ctx, tenantID, comment.FindingID())
	if err != nil {
		// Fail closed: without the approval history the lock cannot be ruled out.
		return fmt.Errorf("check approval decisions: %w", err)
	}
	for _, a := range approvals {
		if commentLockedByApproval(comment, a) {
			return fmt.Errorf("%w: this comment belongs to an approval decision and cannot be changed", shared.ErrForbidden)
		}
	}
	return nil
}

// commentLockedByApproval reports whether the approval locks the comment: a
// participant's comment written from the request on, up to the decision. An
// approved request stays a decision after its acceptance period ends
// (expired), so it keeps its lock. A decided request with no decision time
// locks from the request on (fail closed).
func commentLockedByApproval(c *vulnerability.FindingComment, a *vulnerability.Approval) bool {
	if a == nil || !participant(a, c.AuthorID()) || c.CreatedAt().Before(a.CreatedAt) {
		return false
	}
	var decidedAt *time.Time
	switch a.Status {
	case vulnerability.ApprovalStatusPending:
		return true
	case vulnerability.ApprovalStatusApproved, vulnerability.ApprovalStatusExpired:
		decidedAt = a.ApprovedAt
	case vulnerability.ApprovalStatusRejected:
		decidedAt = a.RejectedAt
	default:
		// Canceled: nothing was decided.
		return false
	}
	return decidedAt == nil || !c.CreatedAt().After(*decidedAt)
}

func participant(a *vulnerability.Approval, id shared.ID) bool {
	if id.IsZero() {
		return false
	}
	if a.RequestedBy == id {
		return true
	}
	return (a.ApprovedBy != nil && *a.ApprovedBy == id) || (a.RejectedBy != nil && *a.RejectedBy == id)
}

// auditCommentChange writes the audit event for an edit or delete of a
// comment. It must succeed before the change is made.
func (s *VulnerabilityService) auditCommentChange(ctx context.Context, action auditdom.Action, msg, actorID string, c *vulnerability.FindingComment) error {
	if s.auditService == nil {
		return nil
	}
	event := audit.NewSuccessEvent(action, auditdom.ResourceTypeFindingComment, c.ID().String()).
		WithMessage(msg).
		WithMetadata("finding_id", c.FindingID().String()).
		WithMetadata("visibility", string(c.Visibility())).
		WithSeverity(auditdom.SeverityMedium)
	actx := audit.AuditContext{TenantID: c.TenantID().String(), ActorID: actorID}
	return s.auditService.LogEvent(ctx, actx, event)
}
