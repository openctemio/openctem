package handler

import (
	"context"
	"net/http"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Organization SSO trust (SAML config, OIDC identity providers, verified
// domains) is changed from the platform admin console on the organization's
// behalf. Those changes decide who can sign in to the organization, so each
// one is written to the organization's own audit log, not only to the admin
// trail. Secrets (client secrets, certificates) are never logged: a change is
// recorded as a flag or a fingerprint.

// orgSSOAuditContext attributes an SSO change to whoever made it: the platform
// admin (actor_email "platform-admin:<email>", no actor_id) when the request
// came through the admin console, otherwise the authenticated user.
func orgSSOAuditContext(r *http.Request) app.AuditContext {
	tenantID := middleware.GetTenantID(r.Context())
	if middleware.GetAdminUser(r.Context()) != nil {
		return adminAuditContext(r, tenantID)
	}
	return app.AuditContext{
		TenantID:   tenantID,
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: auditActorEmail(r.Context()),
		ActorIP:    getClientIP(r),
		UserAgent:  r.UserAgent(),
		RequestID:  r.Header.Get("X-Request-ID"),
	}
}

// logOrgSSOEvent writes event to the organization's audit log. The change has
// already happened, so a failure is logged, not returned.
func logOrgSSOEvent(ctx context.Context, svc *app.AuditService, log *logger.Logger, r *http.Request, event app.AuditEvent) {
	if svc == nil {
		return
	}
	if err := svc.LogEvent(ctx, orgSSOAuditContext(r), event); err != nil {
		log.Error("failed to write organization SSO audit event", "action", string(event.Action), "error", err)
	}
}

// certificateFingerprint is the SHA-256 of a PEM/base64 certificate's
// normalized text, for recording which certificate was configured without
// storing it.
func certificateFingerprint(cert string) string {
	return auth.CertificateFingerprint(cert)
}
