package main

import (
	"context"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	bpapp "github.com/openctemio/openctem/api/internal/app/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// programSyncAuditor records a sync that narrowed or suspended a program
// (RFC-065 §14): as the person who ran it, or as the system.
func programSyncAuditor(svc *auditapp.AuditService) bpapp.SyncAuditor {
	return func(ctx context.Context, p *bp.Program, actor shared.ID, message string, meta map[string]any) {
		if svc == nil {
			return
		}
		actx := auditapp.AuditContext{TenantID: p.TenantID.String()}
		if !actor.IsZero() {
			actx.ActorID = actor.String()
		}
		event := auditapp.NewSuccessEvent(audit.ActionBountyProgramSynced, audit.ResourceTypeBountyProgram, p.ID.String()).
			WithResourceName(p.Name).WithMessage(message).WithMetadata("scope_source", p.ScopeSource)
		for k, v := range meta {
			event = event.WithMetadata(k, v)
		}
		_ = svc.LogEvent(ctx, actx, event)
	}
}
