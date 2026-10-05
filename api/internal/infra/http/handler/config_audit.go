package handler

import (
	"context"
	"net/http"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// configAuditContext is the audit context of a configuration change made
// through this request: the authenticated user, the tenant from the auth
// context (never from the body), client IP (trusted-proxy aware), user agent
// and request id.
func configAuditContext(r *http.Request) auditapp.AuditContext {
	actx := auditapp.AuditContext{
		TenantID:  middleware.GetTenantID(r.Context()),
		ActorID:   middleware.GetUserID(r.Context()),
		ActorIP:   getClientIP(r),
		UserAgent: r.UserAgent(),
		RequestID: r.Header.Get("X-Request-ID"),
	}
	if u := middleware.GetLocalUser(r.Context()); u != nil {
		actx.ActorID = u.ID().String()
		actx.ActorEmail = u.Email()
	}
	if tid := middleware.GetTeamID(r.Context()); !tid.IsZero() {
		actx.TenantID = tid.String()
	}
	return actx
}

// configAuditor is embedded by handlers whose configuration changes are
// audited: it supplies SetAuditService and the record helper.
type configAuditor struct {
	audit *auditapp.AuditService
}

// SetAuditService wires the audit log.
func (c *configAuditor) SetAuditService(a *auditapp.AuditService) { c.audit = a }

func (c *configAuditor) recordChange(r *http.Request, log *logger.Logger, action auditdom.Action, rtype auditdom.ResourceType,
	id, name string, before, after any, severity auditdom.Severity, message string) {
	recordConfigAudit(r.Context(), c.audit, log, configAuditContext(r),
		auditapp.NewChangeEvent(action, rtype, id, before, after).
			WithResourceName(name).
			WithSeverity(severity).
			WithMessage(message))
}

// recordConfigAudit writes a configuration-change event. A nil service is a
// no-op (tests and deployments without audit); a write failure is logged, not
// returned, because the change itself already succeeded.
func recordConfigAudit(ctx context.Context, svc *auditapp.AuditService, log *logger.Logger, actx auditapp.AuditContext, event auditapp.AuditEvent) {
	if svc == nil {
		return
	}
	if err := svc.LogEvent(ctx, actx, event); err != nil && log != nil {
		log.Error("failed to write audit event", "action", string(event.Action), "error", err)
	}
}
