package finding

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The immutable record of status moves and assignments. The finding timeline
// (finding_activities) is deleted with the finding; audit_logs are not, so
// every applied status move and every assignment change also writes an audit
// row with the old and new value and who made it (an empty actor is the
// system). A batch of more than one finding adds one summary row. Best
// effort: an audit write never undoes the move it records.

// auditStatusChanges records the moves a write applied.
func (s *VulnerabilityService) auditStatusChanges(ctx context.Context, tenantID shared.ID, actorID string, changes []statusChange) {
	if s.auditService == nil {
		return
	}
	actx := audit.AuditContext{TenantID: tenantID.String(), ActorID: actorID}
	moved := 0
	for _, c := range changes {
		if c.f == nil || c.old == c.new {
			continue
		}
		moved++
		f := c.f
		event := audit.NewSuccessEvent(auditdom.ActionFindingStatusChanged, auditdom.ResourceTypeFinding, f.ID().String()).
			WithResourceName(f.Title()).
			WithMessage(fmt.Sprintf("Finding status changed from %s to %s", c.old, c.new)).
			WithChanges(auditdom.NewChanges().Set("status", c.old.String(), c.new.String())).
			WithMetadata("old_status", c.old.String()).
			WithMetadata("new_status", c.new.String()).
			WithMetadata("severity", f.Severity().String()).
			WithMetadata("asset_id", f.AssetID().String()).
			WithMetadata("actor_kind", actorKind(actorID)).
			WithSeverity(statusAuditSeverity(f, c.new))
		if cr := f.ClosureReason(); cr != "" && !vulnerability.IsOpenStatus(c.new) {
			event = event.WithMetadata("closure_reason", string(cr))
		}
		if v := f.Verification(); v != "" && !vulnerability.IsOpenStatus(c.new) {
			event = event.WithMetadata("verification", string(v))
		}
		if err := s.auditService.LogEvent(ctx, actx, event); err != nil {
			s.logger.Warn("failed to audit finding status change", "finding_id", f.ID().String(), "error", err)
		}
	}
	if moved > 1 {
		event := audit.NewSuccessEvent(auditdom.ActionFindingBulkUpdated, auditdom.ResourceTypeFinding, "").
			WithMessage(fmt.Sprintf("Changed the status of %d findings", moved)).
			WithMetadata("count", moved).
			WithMetadata("actor_kind", actorKind(actorID)).
			WithSeverity(auditdom.SeverityMedium)
		if err := s.auditService.LogEvent(ctx, actx, event); err != nil {
			s.logger.Warn("failed to audit bulk finding status change", "count", moved, "error", err)
		}
	}
}

// statusAuditSeverity: closing or dispositioning a finding in the critical
// risk tier is high, any other move medium.
func statusAuditSeverity(f *vulnerability.Finding, to vulnerability.FindingStatus) auditdom.Severity {
	if !vulnerability.IsOpenStatus(to) &&
		vulnerability.FindingRiskTier(f.Severity(), priorityClassString(f), f.IsInKEV()) == vulnerability.RiskTierCritical {
		return auditdom.SeverityHigh
	}
	return auditdom.SeverityMedium
}

// assigneeString is the finding's assignee id, or empty.
func assigneeString(f *vulnerability.Finding) string {
	if a := f.AssignedTo(); a != nil && !a.IsZero() {
		return a.String()
	}
	return ""
}

func actorKind(actorID string) string {
	if actorID == "" {
		return "system"
	}
	return "user"
}

// auditAssignment records an assignment change of one finding. assignee is
// empty for an unassignment.
func (s *VulnerabilityService) auditAssignment(ctx context.Context, f *vulnerability.Finding, actorID, previous, assignee string) {
	if s.auditService == nil || f == nil {
		return
	}
	action := auditdom.ActionFindingAssigned
	msg := "Finding assigned"
	if assignee == "" {
		action = auditdom.ActionFindingUnassigned
		msg = "Finding unassigned"
	}
	event := audit.NewSuccessEvent(action, auditdom.ResourceTypeFinding, f.ID().String()).
		WithResourceName(f.Title()).
		WithMessage(msg).
		WithChanges(auditdom.NewChanges().Set("assigned_to", previous, assignee)).
		WithMetadata("previous_assignee", previous).
		WithMetadata("assignee", assignee).
		WithMetadata("asset_id", f.AssetID().String()).
		WithMetadata("actor_kind", actorKind(actorID)).
		WithSeverity(auditdom.SeverityMedium)
	actx := audit.AuditContext{TenantID: f.TenantID().String(), ActorID: actorID}
	if err := s.auditService.LogEvent(ctx, actx, event); err != nil {
		s.logger.Warn("failed to audit finding assignment", "finding_id", f.ID().String(), "error", err)
	}
}
