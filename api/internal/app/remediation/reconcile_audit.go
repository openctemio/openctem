package remediation

import (
	"context"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	remediationdom "github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// systemActor names the actor of a change no person made.
const systemActor = "system"

// systemAuditContext is the audit context of background work in a tenant.
func systemAuditContext(tenantID shared.ID) auditapp.AuditContext {
	return auditapp.AuditContext{TenantID: tenantID.String(), ActorEmail: systemActor}
}

// auditReconcile writes the audit rows of what a background recompute
// changed: a task's derived state (done, verifying, reopened, ...) and the
// regression tasks it opened. A person's own changes are audited where they
// are made.
func (s *TaskService) auditReconcile(ctx context.Context, tenantID shared.ID, rep *remediationdom.RecomputeReport) {
	if rep == nil {
		return
	}
	actx := systemAuditContext(tenantID)
	for _, c := range rep.StateChanges {
		s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionRemediationTaskStateChanged, auditdom.ResourceTypeRemediationTask, c.TaskID.String()).
			WithResourceName(c.Title).
			WithChanges(auditdom.NewChanges().Set("state", string(c.From), string(c.To))).
			WithMessage(fmt.Sprintf("Remediation task %q moved from %s to %s as its findings changed", c.Title, c.From, c.To)).
			WithMetadata("trigger", "reconcile"))
	}
	for _, r := range rep.Regressions {
		s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionRemediationTaskRegressed, auditdom.ResourceTypeRemediationTask, r.TaskID.String()).
			WithResourceName(r.Title).
			WithMessage(fmt.Sprintf("%d finding(s) of closed task %q reopened and moved to a new task", r.Findings, r.SourceTitle)).
			WithMetadata("trigger", "reconcile").
			WithMetadata("regression_of", r.SourceID.String()).
			WithMetadata("findings", r.Findings))
	}
}
