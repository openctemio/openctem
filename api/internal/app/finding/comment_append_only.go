package finding

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// assertCommentNotDecisionLocked refuses a change to a comment written by a
// participant of an approval request while that request was open or after it
// was decided. Such a comment is the justification beside a false-positive,
// acceptance or severity decision and must not be rewritten or removed.
// A request that was canceled or expired decided nothing and locks nothing.
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

// commentLockedByApproval reports whether the approval locks the comment.
func commentLockedByApproval(c *vulnerability.FindingComment, a *vulnerability.Approval) bool {
	if a == nil {
		return false
	}
	author := c.AuthorID()
	switch a.Status {
	case vulnerability.ApprovalStatusPending:
		// open: locked from the request on
		return !c.CreatedAt().Before(a.CreatedAt) && participant(a, author)
	case vulnerability.ApprovalStatusApproved:
		if a.ApprovedAt == nil {
			return false
		}
		return !c.CreatedAt().Before(a.CreatedAt) && !c.CreatedAt().After(*a.ApprovedAt) && participant(a, author)
	case vulnerability.ApprovalStatusRejected:
		if a.RejectedAt == nil {
			return false
		}
		return !c.CreatedAt().Before(a.CreatedAt) && !c.CreatedAt().After(*a.RejectedAt) && participant(a, author)
	default:
		return false
	}
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
