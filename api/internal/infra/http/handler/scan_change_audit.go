package handler

import (
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// logRequestChange writes a tenant audit entry for a change the caller just
// made through the API, attributed like the organization SSO changes (the
// authenticated user, or the platform admin acting on the tenant's behalf).
// Scan profiles and user-issued sensor commands are changed through services
// that do not audit, so their handlers record the change here. The change
// has already happened: a failure is logged, not returned.
func logRequestChange(svc *audit.AuditService, log *logger.Logger, r *http.Request, event audit.AuditEvent) {
	if svc == nil {
		return
	}
	if err := svc.LogEvent(r.Context(), orgSSOAuditContext(r), event); err != nil {
		log.Error("failed to write audit event", "action", string(event.Action), "error", err)
	}
}
