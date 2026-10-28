package routes

// Console route authorization (RFC-134): every console route names the
// platform permission it needs, in adminRoutePermissions. The console routes
// are registered through consolePermRouter, which adds the permission guard
// to each route and refuses (panics) to register a route that is not listed,
// so a console route is denied by default: a new route does not serve until
// it is classified here. The pre-session sign-in steps are routePublic; the
// caller's own session, factors and elevation are routeSelf (a verified
// console session, no permission).

import (
	"fmt"
	"net/http"

	"github.com/openctemio/openctem/api/pkg/domain/platformauthz"
)

const (
	routePublic platformauthz.Permission = "public"
	routeSelf   platformauthz.Permission = "self"
)

// adminRoutePermissions maps "METHOD /pattern" of every console route to its
// permission.
var adminRoutePermissions = map[string]platformauthz.Permission{
	"DELETE /api/v1/admin/auth/elevate":                                      routeSelf,
	"DELETE /api/v1/admin/auth/webauthn/credentials/{id}":                    routeSelf,
	"DELETE /api/v1/admin/console-sessions/{console_session_id}":             platformauthz.AdminsManage,
	"DELETE /api/v1/admin/instance-scan-zones/{zone_id}":                     platformauthz.SensorsManage,
	"DELETE /api/v1/admin/platform-idp/":                                     platformauthz.IdentityManage,
	"DELETE /api/v1/admin/support/sessions/{session_id}":                     platformauthz.SupportAccess,
	"DELETE /api/v1/admin/target-mappings/{id}":                              platformauthz.ContentManage,
	"DELETE /api/v1/admin/tenants/{tenantId}/limits/{key}":                   platformauthz.TenantsLimitsWrite,
	"DELETE /api/v1/admin/tenants/{tenantId}/modules/{module_id}/deny":       platformauthz.TenantsLimitsWrite,
	"DELETE /api/v1/admin/tenants/{tenantId}/sso/identity-providers/{id}":    platformauthz.TenantsSSOWrite,
	"DELETE /api/v1/admin/tenants/{tenantId}/sso/saml":                       platformauthz.TenantsSSOWrite,
	"DELETE /api/v1/admin/tenants/{tenantId}/sso/verified-domains/{id}":      platformauthz.TenantsSSOWrite,
	"DELETE /api/v1/admin/users/{id}":                                        platformauthz.AdminsManage,
	"DELETE /api/v1/admin/users/{id}/idp-binding":                            platformauthz.AdminsManage,
	"GET /api/v1/admin/access-requests/":                                     platformauthz.TenantsRead,
	"GET /api/v1/admin/announcements/":                                       platformauthz.SettingsRead,
	"GET /api/v1/admin/approvals/":                                           platformauthz.ApprovalsRead,
	"GET /api/v1/admin/audit-logs/":                                          platformauthz.AuditRead,
	"GET /api/v1/admin/audit-logs/chain":                                     platformauthz.AuditRead,
	"GET /api/v1/admin/audit-logs/stats":                                     platformauthz.AuditRead,
	"GET /api/v1/admin/audit-logs/{id}":                                      platformauthz.AuditRead,
	"GET /api/v1/admin/auth/factors":                                         routeSelf,
	"GET /api/v1/admin/auth/idp":                                             routePublic,
	"GET /api/v1/admin/auth/validate":                                        routeSelf,
	"GET /api/v1/admin/configuration":                                        platformauthz.ConsoleRead,
	"GET /api/v1/admin/console-sessions/":                                    platformauthz.AdminsRead,
	"GET /api/v1/admin/content-catalog/":                                     platformauthz.SettingsRead,
	"GET /api/v1/admin/content-catalog/packages":                             platformauthz.SettingsRead,
	"GET /api/v1/admin/content-catalog/packages/{namespace}/{name}/versions": platformauthz.SettingsRead,
	"GET /api/v1/admin/content-packs/":                                       platformauthz.SettingsRead,
	"GET /api/v1/admin/content-packs/channels":                               platformauthz.SettingsRead,
	"GET /api/v1/admin/content-packs/signing-key":                            platformauthz.SettingsRead,
	"GET /api/v1/admin/content-packs/{id}":                                   platformauthz.SettingsRead,
	"GET /api/v1/admin/content-packs/{id}/download":                          platformauthz.SettingsRead,
	"GET /api/v1/admin/instance-scan-zones/":                                 platformauthz.SensorsRead,
	"GET /api/v1/admin/instance-scan-zones/{zone_id}":                        platformauthz.SensorsRead,
	"GET /api/v1/admin/mcp-clients/":                                         platformauthz.SettingsRead,
	"GET /api/v1/admin/operations":                                           platformauthz.ConsoleRead,
	"GET /api/v1/admin/overview":                                             platformauthz.ConsoleRead,
	"GET /api/v1/admin/platform-idp/":                                        platformauthz.IdentityManage,
	"GET /api/v1/admin/platform-users/":                                      platformauthz.UsersRead,
	"GET /api/v1/admin/platform-users/{user_id}":                             platformauthz.UsersRead,
	"GET /api/v1/admin/settings/ai/":                                         platformauthz.SettingsRead,
	"GET /api/v1/admin/settings/alerts/":                                     platformauthz.SettingsRead,
	"GET /api/v1/admin/settings/captcha/":                                    platformauthz.SettingsRead,
	"GET /api/v1/admin/settings/console-mfa/":                                platformauthz.SettingsRead,
	"GET /api/v1/admin/settings/email/":                                      platformauthz.SettingsRead,
	"GET /api/v1/admin/settings/legal/":                                      platformauthz.SettingsRead,
	"GET /api/v1/admin/settings/limits/":                                     platformauthz.SettingsRead,
	"GET /api/v1/admin/settings/platform-sensor-proof/":                      platformauthz.SettingsRead,
	"GET /api/v1/admin/settings/region/":                                     platformauthz.SettingsRead,
	"GET /api/v1/admin/settings/scan-approval-policy/":                       platformauthz.SettingsRead,
	"GET /api/v1/admin/settings/shared-sensor-anomaly/":                      platformauthz.SettingsRead,
	"GET /api/v1/admin/settings/shared-sensor-internal-zones/":               platformauthz.SettingsRead,
	"GET /api/v1/admin/settings/shared-sensors/":                             platformauthz.SettingsRead,
	"GET /api/v1/admin/settings/shared-sensors/egress":                       platformauthz.SettingsRead,
	"GET /api/v1/admin/settings/signup-alerts/":                              platformauthz.SettingsRead,
	"GET /api/v1/admin/settings/signup/":                                     platformauthz.SettingsRead,
	"GET /api/v1/admin/settings/storage-quota/":                              platformauthz.SettingsRead,
	"GET /api/v1/admin/shared-sensors/":                                      platformauthz.SensorsRead,
	"GET /api/v1/admin/shared-sensors/jobs":                                  platformauthz.SensorsRead,
	"GET /api/v1/admin/shared-sensors/queue":                                 platformauthz.SensorsRead,
	"GET /api/v1/admin/signup-events/":                                       platformauthz.TenantsRead,
	"GET /api/v1/admin/signup-events/daily":                                  platformauthz.TenantsRead,
	"GET /api/v1/admin/support/grants":                                       platformauthz.SupportAccess,
	"GET /api/v1/admin/support/sessions/{session_id}/assets":                 platformauthz.SupportAccess,
	"GET /api/v1/admin/support/sessions/{session_id}/assets/{id}":            platformauthz.SupportAccess,
	"GET /api/v1/admin/support/sessions/{session_id}/findings":               platformauthz.SupportAccess,
	"GET /api/v1/admin/support/sessions/{session_id}/findings/{id}":          platformauthz.SupportAccess,
	"GET /api/v1/admin/support/sessions/{session_id}/overview":               platformauthz.SupportAccess,
	"GET /api/v1/admin/system":                                               platformauthz.ConsoleRead,
	"GET /api/v1/admin/target-mappings/":                                     platformauthz.SettingsRead,
	"GET /api/v1/admin/target-mappings/stats":                                platformauthz.SettingsRead,
	"GET /api/v1/admin/target-mappings/types":                                platformauthz.SettingsRead,
	"GET /api/v1/admin/target-mappings/{id}":                                 platformauthz.SettingsRead,
	"GET /api/v1/admin/tenants/":                                             platformauthz.TenantsRead,
	"GET /api/v1/admin/tenants/{tenantId}":                                   platformauthz.TenantsRead,
	"GET /api/v1/admin/tenants/{tenantId}/audit-chain":                       platformauthz.TenantsRead,
	"GET /api/v1/admin/tenants/{tenantId}/dashboard-data":                    platformauthz.TenantsRead,
	"GET /api/v1/admin/tenants/{tenantId}/idle":                              platformauthz.TenantsRead,
	"GET /api/v1/admin/tenants/{tenantId}/limits":                            platformauthz.TenantsRead,
	"GET /api/v1/admin/tenants/{tenantId}/modules":                           platformauthz.TenantsRead,
	"GET /api/v1/admin/tenants/{tenantId}/scan-approval-policy":              platformauthz.TenantsRead,
	"GET /api/v1/admin/tenants/{tenantId}/shared-sensors":                    platformauthz.TenantsRead,
	"GET /api/v1/admin/tenants/{tenantId}/sso/changes":                       platformauthz.TenantsRead,
	"GET /api/v1/admin/tenants/{tenantId}/sso/enforcement":                   platformauthz.TenantsRead,
	"GET /api/v1/admin/tenants/{tenantId}/sso/identity-providers":            platformauthz.TenantsRead,
	"GET /api/v1/admin/tenants/{tenantId}/sso/identity-providers/{id}":       platformauthz.TenantsRead,
	"GET /api/v1/admin/tenants/{tenantId}/sso/saml":                          platformauthz.TenantsRead,
	"GET /api/v1/admin/tenants/{tenantId}/sso/verified-domains":              platformauthz.TenantsRead,
	"GET /api/v1/admin/tenants/{tenantId}/users":                             platformauthz.TenantsRead,
	"GET /api/v1/admin/threat-intel/sync":                                    platformauthz.SettingsRead,
	"GET /api/v1/admin/users/":                                               platformauthz.AdminsRead,
	"GET /api/v1/admin/users/{id}":                                           platformauthz.AdminsRead,
	"GET /api/v1/admin/version":                                              platformauthz.ConsoleRead,
	"GET /api/v1/admin/version-check/":                                       platformauthz.SettingsRead,
	"PATCH /api/v1/admin/auth/webauthn/credentials/{id}":                     routeSelf,
	"PATCH /api/v1/admin/target-mappings/{id}":                               platformauthz.ContentManage,
	"PATCH /api/v1/admin/tenants/{tenantId}/sso/verified-domains/{id}":       platformauthz.TenantsSSOWrite,
	"PATCH /api/v1/admin/threat-intel/sync/{source}":                         platformauthz.FeedsManage,
	"PATCH /api/v1/admin/users/{id}":                                         platformauthz.AdminsManage,
	"POST /api/v1/admin/access-requests/{id}/approve":                        platformauthz.TenantsCreate,
	"POST /api/v1/admin/access-requests/{id}/reject":                         platformauthz.TenantsCreate,
	"POST /api/v1/admin/administrators/":                                     platformauthz.AdminsManage,
	"POST /api/v1/admin/announcements/":                                      platformauthz.AnnouncementsWrite,
	"POST /api/v1/admin/announcements/{announcement_id}/cancel":              platformauthz.AnnouncementsWrite,
	"POST /api/v1/admin/approvals/":                                          platformauthz.ApprovalsDecide,
	"POST /api/v1/admin/approvals/{id}/approve":                              platformauthz.ApprovalsDecide,
	"POST /api/v1/admin/approvals/{id}/cancel":                               platformauthz.ApprovalsDecide,
	"POST /api/v1/admin/approvals/{id}/reject":                               platformauthz.ApprovalsDecide,
	"POST /api/v1/admin/auth/elevate":                                        routeSelf,
	"POST /api/v1/admin/auth/idp/callback":                                   routePublic,
	"POST /api/v1/admin/auth/idp/start":                                      routePublic,
	"POST /api/v1/admin/auth/login":                                          routePublic,
	"POST /api/v1/admin/auth/logout":                                         routePublic,
	"POST /api/v1/admin/auth/mfa":                                            routePublic,
	"POST /api/v1/admin/auth/password":                                       routeSelf,
	"POST /api/v1/admin/auth/recovery":                                       routePublic,
	"POST /api/v1/admin/auth/recovery-codes":                                 routeSelf,
	"POST /api/v1/admin/auth/step-up/webauthn":                               routeSelf,
	"POST /api/v1/admin/auth/step-up/webauthn/options":                       routeSelf,
	"POST /api/v1/admin/auth/webauthn/credentials":                           routeSelf,
	"POST /api/v1/admin/auth/webauthn/credentials/options":                   routeSelf,
	"POST /api/v1/admin/auth/webauthn/session":                               routePublic,
	"POST /api/v1/admin/auth/webauthn/session/options":                       routePublic,
	"POST /api/v1/admin/content-catalog/import":                              platformauthz.ContentManage,
	"POST /api/v1/admin/content-catalog/packages":                            platformauthz.ContentManage,
	"POST /api/v1/admin/content-catalog/packages/revoke":                     platformauthz.ContentManage,
	"POST /api/v1/admin/content-packs/":                                      platformauthz.ContentManage,
	"POST /api/v1/admin/content-packs/import":                                platformauthz.ContentManage,
	"POST /api/v1/admin/content-packs/{id}/revoke":                           platformauthz.ContentManage,
	"POST /api/v1/admin/instance-scan-zones/":                                platformauthz.SensorsManage,
	"POST /api/v1/admin/mcp-clients/{id}/block":                              platformauthz.AIClientsManage,
	"POST /api/v1/admin/mcp-clients/{id}/unblock":                            platformauthz.AIClientsManage,
	"POST /api/v1/admin/platform-users/{user_id}/block":                      platformauthz.UsersSupport,
	"POST /api/v1/admin/platform-users/{user_id}/password-reset":             platformauthz.UsersSupport,
	"POST /api/v1/admin/platform-users/{user_id}/revoke-sessions":            platformauthz.UsersSupport,
	"POST /api/v1/admin/platform-users/{user_id}/unblock":                    platformauthz.UsersSupport,
	"POST /api/v1/admin/platform-users/{user_id}/unlock":                     platformauthz.UsersSupport,
	"POST /api/v1/admin/platform-users/{user_id}/verification-emails":        platformauthz.UsersSupport,
	"POST /api/v1/admin/settings/ai/test":                                    platformauthz.SettingsAIWrite,
	"POST /api/v1/admin/settings/alerts/test":                                platformauthz.SettingsGeneralWrite,
	"POST /api/v1/admin/settings/captcha/verify":                             platformauthz.SettingsGeneralWrite,
	"POST /api/v1/admin/settings/email/test":                                 platformauthz.SettingsEmailWrite,
	"POST /api/v1/admin/shared-sensors/enrollment-tokens":                    platformauthz.SensorsManage,
	"POST /api/v1/admin/shared-sensors/jobs/{job_id}/view":                   platformauthz.SensorsJobsRead,
	"POST /api/v1/admin/shared-sensors/{sensor_id}/disable":                  platformauthz.SensorsManage,
	"POST /api/v1/admin/shared-sensors/{sensor_id}/enable":                   platformauthz.SensorsManage,
	"POST /api/v1/admin/shared-sensors/{sensor_id}/revoke":                   platformauthz.SensorsManage,
	"POST /api/v1/admin/support/grants/{grant_id}/sessions":                  platformauthz.SupportAccess,
	"POST /api/v1/admin/target-mappings/":                                    platformauthz.ContentManage,
	"POST /api/v1/admin/tenants/":                                            platformauthz.TenantsCreate,
	"POST /api/v1/admin/tenants/{tenantId}/audit-chain/rebaseline":           platformauthz.TenantsAuditChainWrite,
	"POST /api/v1/admin/tenants/{tenantId}/dashboard-data/rebuild":           platformauthz.TenantsLifecycle,
	"POST /api/v1/admin/tenants/{tenantId}/purge":                            platformauthz.TenantsPurge,
	"POST /api/v1/admin/tenants/{tenantId}/sso/identity-providers":           platformauthz.TenantsSSOWrite,
	"POST /api/v1/admin/tenants/{tenantId}/sso/verified-domains":             platformauthz.TenantsSSOWrite,
	"POST /api/v1/admin/tenants/{tenantId}/sso/verified-domains/{id}/verify": platformauthz.TenantsSSOWrite,
	"POST /api/v1/admin/tenants/{tenantId}/suspend":                          platformauthz.TenantsLifecycle,
	"POST /api/v1/admin/tenants/{tenantId}/unsuspend":                        platformauthz.TenantsLifecycle,
	"POST /api/v1/admin/tenants/{tenantId}/users":                            platformauthz.TenantsOwnerBootstrap,
	"POST /api/v1/admin/threat-intel/sync":                                   platformauthz.FeedsManage,
	"POST /api/v1/admin/users/{id}/break-glass-test":                         platformauthz.AdminsManage,
	"POST /api/v1/admin/users/{id}/reset-credentials":                        platformauthz.AdminsManage,
	"POST /api/v1/admin/version-check/import":                                platformauthz.SettingsGeneralWrite,
	"PUT /api/v1/admin/content-packs/channels/{channel}":                     platformauthz.ContentManage,
	"PUT /api/v1/admin/instance-scan-zones/{zone_id}":                        platformauthz.SensorsManage,
	"PUT /api/v1/admin/instance-scan-zones/{zone_id}/organizations":          platformauthz.SensorsManage,
	"PUT /api/v1/admin/instance-scan-zones/{zone_id}/sensors":                platformauthz.SensorsManage,
	"PUT /api/v1/admin/platform-idp/":                                        platformauthz.IdentityManage,
	"PUT /api/v1/admin/settings/ai/":                                         platformauthz.SettingsAIWrite,
	"PUT /api/v1/admin/settings/ai/org-policy":                               platformauthz.SettingsAIWrite,
	"PUT /api/v1/admin/settings/alerts/":                                     platformauthz.SettingsGeneralWrite,
	"PUT /api/v1/admin/settings/captcha/":                                    platformauthz.SettingsGeneralWrite,
	"PUT /api/v1/admin/settings/console-mfa/":                                platformauthz.IdentityManage,
	"PUT /api/v1/admin/settings/email/":                                      platformauthz.SettingsEmailWrite,
	"PUT /api/v1/admin/settings/legal/":                                      platformauthz.SettingsLegalWrite,
	"PUT /api/v1/admin/settings/limits/":                                     platformauthz.SettingsLimitsWrite,
	"PUT /api/v1/admin/settings/platform-sensor-proof/":                      platformauthz.SensorsManage,
	"PUT /api/v1/admin/settings/region/":                                     platformauthz.SettingsGeneralWrite,
	"PUT /api/v1/admin/settings/scan-approval-policy/":                       platformauthz.SensorsManage,
	"PUT /api/v1/admin/settings/shared-sensor-anomaly/":                      platformauthz.SensorsManage,
	"PUT /api/v1/admin/settings/shared-sensor-internal-zones/":               platformauthz.SensorsManage,
	"PUT /api/v1/admin/settings/shared-sensors/":                             platformauthz.SensorsManage,
	"PUT /api/v1/admin/settings/shared-sensors/egress":                       platformauthz.SensorsManage,
	"PUT /api/v1/admin/settings/signup-alerts/":                              platformauthz.SettingsSignupWrite,
	"PUT /api/v1/admin/settings/signup/":                                     platformauthz.SettingsSignupWrite,
	"PUT /api/v1/admin/settings/storage-quota/":                              platformauthz.SettingsGeneralWrite,
	"PUT /api/v1/admin/tenants/{tenantId}/idle/policy":                       platformauthz.TenantsLimitsWrite,
	"PUT /api/v1/admin/tenants/{tenantId}/limits/{key}":                      platformauthz.TenantsLimitsWrite,
	"PUT /api/v1/admin/tenants/{tenantId}/modules/{module_id}/deny":          platformauthz.TenantsLimitsWrite,
	"PUT /api/v1/admin/tenants/{tenantId}/scan-approval-policy":              platformauthz.TenantsScanPolicyWrite,
	"PUT /api/v1/admin/tenants/{tenantId}/shared-sensors":                    platformauthz.TenantsScanPolicyWrite,
	"PUT /api/v1/admin/tenants/{tenantId}/sso/enforcement":                   platformauthz.TenantsSSOWrite,
	"PUT /api/v1/admin/tenants/{tenantId}/sso/identity-providers/{id}":       platformauthz.TenantsSSOWrite,
	"PUT /api/v1/admin/tenants/{tenantId}/sso/saml":                          platformauthz.TenantsSSOWrite,
	"PUT /api/v1/admin/version-check/enabled":                                platformauthz.SettingsGeneralWrite,
	"GET /api/v1/admin/openapi.yaml":                                         platformauthz.ConsoleRead,
	"GET /api/v1/admin/docs":                                                 platformauthz.ConsoleRead,
}

// consolePermRouter registers console routes with their permission guard.
type consolePermRouter struct {
	Router
	prefix string
	guard  func(platformauthz.Permission) Middleware
}

func newConsolePermRouter(r Router, guard func(platformauthz.Permission) Middleware) Router {
	return &consolePermRouter{Router: r, guard: guard}
}

func (r *consolePermRouter) chain(method, path string, mws []Middleware) []Middleware {
	key := method + " " + r.prefix + path
	p, ok := adminRoutePermissions[key]
	if !ok {
		panic(fmt.Sprintf("console route %q has no platform permission: add it to adminRoutePermissions", key))
	}
	if p == routePublic || p == routeSelf {
		return mws
	}
	if !platformauthz.Known(p) {
		panic(fmt.Sprintf("console route %q names unknown permission %q", key, p))
	}
	return append([]Middleware{r.guard(p)}, mws...)
}

func (r *consolePermRouter) GET(path string, h http.HandlerFunc, mws ...Middleware) {
	r.Router.GET(path, h, r.chain(http.MethodGet, path, mws)...)
}

func (r *consolePermRouter) POST(path string, h http.HandlerFunc, mws ...Middleware) {
	r.Router.POST(path, h, r.chain(http.MethodPost, path, mws)...)
}

func (r *consolePermRouter) PUT(path string, h http.HandlerFunc, mws ...Middleware) {
	r.Router.PUT(path, h, r.chain(http.MethodPut, path, mws)...)
}

func (r *consolePermRouter) PATCH(path string, h http.HandlerFunc, mws ...Middleware) {
	r.Router.PATCH(path, h, r.chain(http.MethodPatch, path, mws)...)
}

func (r *consolePermRouter) DELETE(path string, h http.HandlerFunc, mws ...Middleware) {
	r.Router.DELETE(path, h, r.chain(http.MethodDelete, path, mws)...)
}

func (r *consolePermRouter) Group(prefix string, fn func(Router), mws ...Middleware) {
	r.Router.Group(prefix, func(g Router) {
		fn(&consolePermRouter{Router: g, prefix: r.prefix + prefix, guard: r.guard})
	}, mws...)
}

func (r *consolePermRouter) With(mws ...Middleware) Router {
	return &consolePermRouter{Router: r.Router.With(mws...), prefix: r.prefix, guard: r.guard}
}
