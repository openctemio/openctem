package auth

import (
	"context"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// clientInfoKey carries the signing-in browser's address and user agent from
// the HTTP handler to the session it opens.
type clientInfoKey struct{}

// ClientInfo is the browser that signs in: its address (resolved by the
// handler through the trusted-proxy rules) and its user agent.
type ClientInfo struct {
	IP        string
	UserAgent string
}

// WithClientInfo returns ctx carrying the signing-in browser's address and
// user agent, for the federated sign-ins (SSO, SAML, social OAuth) whose
// service calls take no request.
func WithClientInfo(ctx context.Context, ip, userAgent string) context.Context {
	return context.WithValue(ctx, clientInfoKey{}, ClientInfo{IP: ip, UserAgent: userAgent})
}

func clientInfoFrom(ctx context.Context) ClientInfo {
	ci, _ := ctx.Value(clientInfoKey{}).(ClientInfo)
	return ci
}

// auditFederatedLogin writes auth.login for a sign-in through an identity
// provider, with the method (sso, saml, oauth) and the provider, the same
// event a password sign-in writes. tenantID is the organization whose
// identity provider issued the sign-in (empty for social sign-in), so the
// event shows in that organization's audit log. Failures are logged, never
// returned.
func auditFederatedLogin(ctx context.Context, svc *auditapp.AuditService, log *logger.Logger,
	u *userdom.User, tenantID, sessionID, method, provider string,
) {
	if svc == nil {
		return
	}
	ci := clientInfoFrom(ctx)
	ev := auditapp.NewSuccessEvent(auditdom.ActionAuthLogin, auditdom.ResourceTypeUser, u.ID().String()).
		WithResourceName(u.Email()).
		WithMessage("User "+u.Email()+" logged in through "+method).
		WithMetadata("method", method)
	if provider != "" {
		ev = ev.WithMetadata("provider", provider)
	}
	actx := auditapp.AuditContext{
		TenantID: tenantID,
		ActorID:  u.ID().String(), ActorEmail: u.Email(), ActorIP: ci.IP, UserAgent: ci.UserAgent, SessionID: sessionID,
	}
	if err := svc.LogEvent(ctx, actx, ev); err != nil && log != nil {
		log.Error("failed to audit federated login", "method", method, "error", err)
	}
}

// auditSocialRefusedSSOIdentity records a social sign-in refused because its
// provider key belongs to an identity organization single sign-on manages
// (auth.failed, denied). The event carries the user id and the provider only.
func auditSocialRefusedSSOIdentity(ctx context.Context, svc *auditapp.AuditService, log *logger.Logger,
	u *userdom.User, provider string,
) {
	if svc == nil {
		return
	}
	ci := clientInfoFrom(ctx)
	ev := auditapp.NewDeniedEvent(auditdom.ActionAuthFailed, auditdom.ResourceTypeUser, u.ID().String(), "social_sign_in_on_sso_identity").
		WithMessage("Social sign-in refused: the account signs in through its organization").
		WithMetadata("method", "oauth").
		WithMetadata("provider", provider)
	actx := auditapp.AuditContext{ActorID: u.ID().String(), ActorIP: ci.IP, UserAgent: ci.UserAgent}
	if err := svc.LogEvent(ctx, actx, ev); err != nil && log != nil {
		log.Error("failed to audit refused social sign-in", "error", err)
	}
}
