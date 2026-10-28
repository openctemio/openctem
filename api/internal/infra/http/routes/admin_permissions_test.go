package routes

// Console authorization by platform permission (RFC-134), over the real
// console route registration:
//
//   - every console route is classified in adminRoutePermissions, every entry
//     is a registered route, and registering an unclassified route panics
//     (deny by default);
//   - the three tiers keep exactly the routes they had before platform roles
//     (legacyMinimumTier below is that matrix);
//   - each built-in role reaches exactly the routes its permissions name, and
//     an administrator with no role reaches none;
//   - with elevation required, an unelevated owner reaches only the reads.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformauthz"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// legacyMinimumTier is the console's route matrix before platform roles:
// routes that needed ops_admin or super_admin (every other console route was
// open to any administrator).
var legacyMinimumTier = map[string]admin.AdminRole{
	// Added with platform roles: the roster and role changes are owner-only.
	"GET /api/v1/admin/platform-roles/assignments":                           admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/users/{id}/platform-roles":                           admin.AdminRoleSuperAdmin,
	"DELETE /api/v1/admin/users/{id}/platform-roles/{role}":                  admin.AdminRoleSuperAdmin,
	"DELETE /api/v1/admin/console-sessions/{console_session_id}":             admin.AdminRoleSuperAdmin,
	"DELETE /api/v1/admin/instance-scan-zones/{zone_id}":                     admin.AdminRoleSuperAdmin,
	"DELETE /api/v1/admin/platform-idp/":                                     admin.AdminRoleSuperAdmin,
	"DELETE /api/v1/admin/target-mappings/{id}":                              admin.AdminRoleSuperAdmin,
	"DELETE /api/v1/admin/tenants/{tenantId}/limits/{key}":                   admin.AdminRoleOpsAdmin,
	"DELETE /api/v1/admin/tenants/{tenantId}/modules/{module_id}/deny":       admin.AdminRoleOpsAdmin,
	"DELETE /api/v1/admin/tenants/{tenantId}/sso/identity-providers/{id}":    admin.AdminRoleSuperAdmin,
	"DELETE /api/v1/admin/tenants/{tenantId}/sso/saml":                       admin.AdminRoleSuperAdmin,
	"DELETE /api/v1/admin/tenants/{tenantId}/sso/verified-domains/{id}":      admin.AdminRoleSuperAdmin,
	"DELETE /api/v1/admin/users/{id}":                                        admin.AdminRoleSuperAdmin,
	"DELETE /api/v1/admin/users/{id}/idp-binding":                            admin.AdminRoleSuperAdmin,
	"GET /api/v1/admin/approvals/":                                           admin.AdminRoleSuperAdmin,
	"GET /api/v1/admin/console-sessions/":                                    admin.AdminRoleSuperAdmin,
	"GET /api/v1/admin/platform-idp/":                                        admin.AdminRoleSuperAdmin,
	"GET /api/v1/admin/platform-users/":                                      admin.AdminRoleOpsAdmin,
	"GET /api/v1/admin/platform-users/{user_id}":                             admin.AdminRoleOpsAdmin,
	"GET /api/v1/admin/support/grants":                                       admin.AdminRoleOpsAdmin,
	"GET /api/v1/admin/users/":                                               admin.AdminRoleSuperAdmin,
	"GET /api/v1/admin/users/{id}":                                           admin.AdminRoleSuperAdmin,
	"PATCH /api/v1/admin/target-mappings/{id}":                               admin.AdminRoleSuperAdmin,
	"PATCH /api/v1/admin/tenants/{tenantId}/sso/verified-domains/{id}":       admin.AdminRoleSuperAdmin,
	"PATCH /api/v1/admin/threat-intel/sync/{source}":                         admin.AdminRoleOpsAdmin,
	"PATCH /api/v1/admin/users/{id}":                                         admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/access-requests/{id}/approve":                        admin.AdminRoleOpsAdmin,
	"POST /api/v1/admin/access-requests/{id}/reject":                         admin.AdminRoleOpsAdmin,
	"POST /api/v1/admin/administrators/":                                     admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/announcements/":                                      admin.AdminRoleOpsAdmin,
	"POST /api/v1/admin/announcements/{announcement_id}/cancel":              admin.AdminRoleOpsAdmin,
	"POST /api/v1/admin/approvals/":                                          admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/approvals/{id}/approve":                              admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/approvals/{id}/cancel":                               admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/approvals/{id}/reject":                               admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/content-catalog/import":                              admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/content-catalog/packages":                            admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/content-catalog/packages/revoke":                     admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/content-packs/":                                      admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/content-packs/import":                                admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/content-packs/{id}/revoke":                           admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/instance-scan-zones/":                                admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/mcp-clients/{id}/block":                              admin.AdminRoleOpsAdmin,
	"POST /api/v1/admin/mcp-clients/{id}/unblock":                            admin.AdminRoleOpsAdmin,
	"POST /api/v1/admin/platform-users/{user_id}/block":                      admin.AdminRoleOpsAdmin,
	"POST /api/v1/admin/platform-users/{user_id}/password-reset":             admin.AdminRoleOpsAdmin,
	"POST /api/v1/admin/platform-users/{user_id}/revoke-sessions":            admin.AdminRoleOpsAdmin,
	"POST /api/v1/admin/platform-users/{user_id}/unblock":                    admin.AdminRoleOpsAdmin,
	"POST /api/v1/admin/platform-users/{user_id}/unlock":                     admin.AdminRoleOpsAdmin,
	"POST /api/v1/admin/platform-users/{user_id}/verification-emails":        admin.AdminRoleOpsAdmin,
	"POST /api/v1/admin/settings/ai/test":                                    admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/settings/alerts/test":                                admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/settings/captcha/verify":                             admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/settings/email/test":                                 admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/shared-sensors/enrollment-tokens":                    admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/shared-sensors/jobs/{job_id}/view":                   admin.AdminRoleOpsAdmin,
	"POST /api/v1/admin/shared-sensors/{sensor_id}/disable":                  admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/shared-sensors/{sensor_id}/enable":                   admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/shared-sensors/{sensor_id}/revoke":                   admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/support/grants/{grant_id}/sessions":                  admin.AdminRoleOpsAdmin,
	"POST /api/v1/admin/target-mappings/":                                    admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/tenants/":                                            admin.AdminRoleOpsAdmin,
	"POST /api/v1/admin/tenants/{tenantId}/audit-chain/rebaseline":           admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/tenants/{tenantId}/dashboard-data/rebuild":           admin.AdminRoleOpsAdmin,
	"POST /api/v1/admin/tenants/{tenantId}/purge":                            admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/tenants/{tenantId}/sso/identity-providers":           admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/tenants/{tenantId}/sso/verified-domains":             admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/tenants/{tenantId}/sso/verified-domains/{id}/verify": admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/tenants/{tenantId}/suspend":                          admin.AdminRoleOpsAdmin,
	"POST /api/v1/admin/tenants/{tenantId}/unsuspend":                        admin.AdminRoleOpsAdmin,
	"POST /api/v1/admin/tenants/{tenantId}/users":                            admin.AdminRoleOpsAdmin,
	"POST /api/v1/admin/threat-intel/sync":                                   admin.AdminRoleOpsAdmin,
	"POST /api/v1/admin/users/{id}/break-glass-test":                         admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/users/{id}/reset-credentials":                        admin.AdminRoleSuperAdmin,
	"POST /api/v1/admin/version-check/import":                                admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/content-packs/channels/{channel}":                     admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/instance-scan-zones/{zone_id}":                        admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/instance-scan-zones/{zone_id}/organizations":          admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/instance-scan-zones/{zone_id}/sensors":                admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/platform-idp/":                                        admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/settings/ai/":                                         admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/settings/ai/org-policy":                               admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/settings/alerts/":                                     admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/settings/captcha/":                                    admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/settings/console-mfa/":                                admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/settings/email/":                                      admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/settings/email-relay/":                                admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/settings/legal/":                                      admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/settings/limits/":                                     admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/settings/platform-sensor-proof/":                      admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/settings/region/":                                     admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/settings/scan-approval-policy/":                       admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/settings/shared-sensor-anomaly/":                      admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/settings/shared-sensor-internal-zones/":               admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/settings/shared-sensors/":                             admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/settings/shared-sensors/egress":                       admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/settings/signup-alerts/":                              admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/settings/signup/":                                     admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/settings/storage-quota/":                              admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/tenants/{tenantId}/idle/policy":                       admin.AdminRoleOpsAdmin,
	"PUT /api/v1/admin/tenants/{tenantId}/limits/{key}":                      admin.AdminRoleOpsAdmin,
	"PUT /api/v1/admin/tenants/{tenantId}/modules/{module_id}/deny":          admin.AdminRoleOpsAdmin,
	"PUT /api/v1/admin/tenants/{tenantId}/scan-approval-policy":              admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/tenants/{tenantId}/shared-sensors":                    admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/tenants/{tenantId}/sso/enforcement":                   admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/tenants/{tenantId}/sso/identity-providers/{id}":       admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/tenants/{tenantId}/sso/saml":                          admin.AdminRoleSuperAdmin,
	"PUT /api/v1/admin/version-check/enabled":                                admin.AdminRoleSuperAdmin,
}

type fixedPlatformRoles []platformauthz.RoleKey

func (f fixedPlatformRoles) HeldRoles(context.Context, string) ([]platformauthz.RoleKey, error) {
	return f, nil
}

// consoleRoutes lists "METHOD /pattern" of every registered console route.
func consoleRoutes(router infrahttp.Router) []string {
	var out []string
	_ = router.Walk(func(method, path string, _ http.Handler) error {
		if strings.HasPrefix(path, "/api/v1/admin") {
			out = append(out, method+" "+path)
		}
		return nil
	})
	return out
}

// callConsole sends one request to a console route and returns the status.
func callConsole(h http.Handler, key string) int {
	method, path, _ := strings.Cut(key, " ")
	path = strings.NewReplacer("{tenantId}", shared.NewID().String(), "{module_id}", "pentest",
		"{key}", "seats", "{channel}", "stable", "{source}", "epss", "{namespace}", "acme",
		"{name}", "words", "{version}", "1.0.0").Replace(path)
	for strings.Contains(path, "{") {
		i, j := strings.Index(path, "{"), strings.Index(path, "}")
		path = path[:i] + shared.NewID().String() + path[j+1:]
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
	req.AddCookie(&http.Cookie{Name: middleware.AdminSessionCookie, Value: "s"})
	req.Header.Set(middleware.CSRFHeaderName, middleware.AdminCSRFToken("s"))
	func() {
		// A zero-value handler may panic once reached; reaching it is the point.
		defer func() { _ = recover() }()
		h.ServeHTTP(rec, req)
	}()
	return rec.Code
}

// routerAs is the console router with every request authenticated as an
// administrator of tier holding roles (nil roles: the tier's base role).
func routerAs(t *testing.T, tier admin.AdminRole, roles []platformauthz.RoleKey, elevation bool) http.Handler {
	t.Helper()
	now := time.Now()
	router, _, _ := inventoryRouterRole(t, tier, func(h *Handlers) {
		a := admin.Reconstitute(shared.NewID(), "root@example.com", "Root", tier, true, nil, nil, "", 0, nil, nil, "", now, nil, now)
		m := middleware.NewAdminAuthMiddleware(inventorySessions{a}, logger.NewNop()).WithElevation(elevation)
		if roles != nil {
			m = m.WithPlatformRoles(fixedPlatformRoles(roles))
		}
		h.AdminAuthMiddleware = m
	})
	return router.Handler()
}

// handlerMayRefuse lists routes whose handler answers 403 by itself on a
// made-up id (a support session that is not the caller's).
func handlerMayRefuse(key string) bool {
	return strings.Contains(key, "/api/v1/admin/support/sessions/")
}

func TestAdminRoutePermissionsComplete(t *testing.T) {
	router, _ := inventoryRouter(t)
	routes := consoleRoutes(router)
	if len(routes) < 150 {
		t.Fatalf("only %d console routes registered: the inventory router lost routes", len(routes))
	}
	seen := map[string]bool{"GET /api/v1/admin/openapi.yaml": true, "GET /api/v1/admin/docs": true} // registerDocsRoutes
	used := map[platformauthz.Permission]bool{}
	for _, key := range routes {
		seen[key] = true
		p, ok := adminRoutePermissions[key]
		if !ok {
			t.Errorf("console route %q has no platform permission", key)
			continue
		}
		used[p] = true
		if p != routePublic && p != routeSelf && !platformauthz.Known(p) {
			t.Errorf("%s names unknown permission %q", key, p)
		}
		if p == routePublic && !strings.HasPrefix(key, "POST /api/v1/admin/auth/") && key != "GET /api/v1/admin/auth/idp" {
			t.Errorf("%s: only the sign-in steps are public", key)
		}
		if p == routeSelf && !strings.Contains(key, "/api/v1/admin/auth/") {
			t.Errorf("%s: only the caller's own session routes are self", key)
		}
	}
	for key := range adminRoutePermissions {
		if !seen[key] {
			t.Errorf("adminRoutePermissions lists %q but no such route is registered", key)
		}
	}
	// Every permission guards a route, except the ones a handler checks for
	// part of a response or request (member e-mails, owner recovery).
	reserved := map[platformauthz.Permission]bool{
		platformauthz.TenantsMembersRead: true, platformauthz.TenantsOwnerRecovery: true,
	}
	for _, d := range platformauthz.Catalog() {
		if !used[d.Key] && !reserved[d.Key] {
			t.Errorf("permission %s guards no route", d.Key)
		}
	}
}

func TestConsoleRouteWithoutPermissionPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("registering an unclassified console route must panic")
		}
	}()
	r := newConsolePermRouter(infrahttp.NewChiRouter(), func(platformauthz.Permission) Middleware { return nil })
	r.GET("/api/v1/admin/brand-new", func(http.ResponseWriter, *http.Request) {})
}

// The three tiers keep the routes they had: their base roles are the old
// tiers exactly.
func TestLegacyTiersKeepTheirRoutes(t *testing.T) {
	router, _ := inventoryRouter(t)
	rank := map[admin.AdminRole]int{admin.AdminRoleReadonly: 1, admin.AdminRoleOpsAdmin: 2, admin.AdminRoleSuperAdmin: 3}
	for _, tier := range []admin.AdminRole{admin.AdminRoleReadonly, admin.AdminRoleOpsAdmin, admin.AdminRoleSuperAdmin} {
		h := routerAs(t, tier, nil, false)
		for _, key := range consoleRoutes(router) {
			if p := adminRoutePermissions[key]; p == routePublic || p == routeSelf {
				continue
			}
			need, ok := legacyMinimumTier[key]
			if !ok {
				need = admin.AdminRoleReadonly
			}
			allowed := rank[tier] >= rank[need]
			code := callConsole(h, key)
			switch {
			case !allowed && code != http.StatusForbidden:
				t.Errorf("%s as %s: %d, want 403 (it needed %s)", key, tier, code, need)
			case allowed && code == http.StatusForbidden && !handlerMayRefuse(key):
				t.Errorf("%s as %s: 403, but %s had it", key, tier, tier)
			}
		}
	}
}

// Each built-in role reaches exactly the routes its permissions name; no
// role, no route.
func TestPlatformRoleRouteMatrix(t *testing.T) {
	router, _ := inventoryRouter(t)
	routes := consoleRoutes(router)
	roles := append([][]platformauthz.RoleKey{{}}, func() (out [][]platformauthz.RoleKey) {
		for _, r := range platformauthz.BuiltinRoles() {
			out = append(out, []platformauthz.RoleKey{r.Key})
		}
		return out
	}()...)
	for _, held := range roles {
		h := routerAs(t, admin.AdminRoleReadonly, held, false)
		perms := platformauthz.Held(held)
		name := "no role"
		if len(held) > 0 {
			name = string(held[0])
		}
		for _, key := range routes {
			p := adminRoutePermissions[key]
			if p == routePublic || p == routeSelf {
				continue
			}
			code := callConsole(h, key)
			switch {
			case !perms.Has(p) && code != http.StatusForbidden:
				t.Errorf("%s as %s: %d, want 403 (needs %s)", key, name, code, p)
			case perms.Has(p) && code == http.StatusForbidden && !handlerMayRefuse(key):
				t.Errorf("%s as %s: 403, but the role holds %s", key, name, p)
			}
		}
	}
}

// With elevation required, an owner that has not elevated reaches only the
// baseline reads.
func TestUnelevatedOwnerReadsOnly(t *testing.T) {
	router, _ := inventoryRouter(t)
	h := routerAs(t, admin.AdminRoleSuperAdmin, []platformauthz.RoleKey{platformauthz.RoleOwner}, true)
	for _, key := range consoleRoutes(router) {
		p := adminRoutePermissions[key]
		if p == routePublic || p == routeSelf {
			continue
		}
		code := callConsole(h, key)
		if !platformauthz.Baseline(p) && code != http.StatusForbidden {
			t.Errorf("%s unelevated: %d, want 403 (%s is not a baseline read)", key, code, p)
		}
	}
}
