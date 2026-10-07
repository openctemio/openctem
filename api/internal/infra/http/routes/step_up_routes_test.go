package routes

// Step-up re-authentication on the sensitive routes
// (docs/architecture/step-up-reauth.md): every route in stepUpRoutes answers
// 403 STEP_UP_REQUIRED when the caller's session has not authenticated within
// the window, and reaches its handler when it has. The caller is an owner
// with every permission, so nothing but step-up can refuse it.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// alwaysSteppedUp is a step-up checker for route tests that are not about
// step-up: every session has just authenticated.
type alwaysSteppedUp struct{}

func (alwaysSteppedUp) RecentAuthAt(context.Context, string, string) (time.Time, error) {
	return time.Now(), nil
}

// steppedUpAt answers a fixed time for every session.
type steppedUpAt time.Time

func (s steppedUpAt) RecentAuthAt(context.Context, string, string) (time.Time, error) {
	return time.Time(s), nil
}

// withStepUpChecker sets the package checker for routes registered by this
// test (registration captures it) and restores it afterwards.
func withStepUpChecker(t *testing.T, c middleware.RecentAuthChecker) {
	t.Helper()
	saved := stepUpChecker
	stepUpChecker = c
	t.Cleanup(func() { stepUpChecker = saved })
}

// stepUpRoutes is every route that requires step-up. Adding requireStepUp()
// to a route means adding it here.
var stepUpRoutes = []string{
	"POST /api/v1/api-keys",
	"DELETE /api/v1/api-keys/{id}",
	"POST /api/v1/scim-tokens",
	"POST /api/v1/ci/gate-overrides",
	"PATCH /api/v1/tenants/acme/settings/security",
	"POST /api/v1/tenants/acme/settings/sso/changes/{id}/approve",
	"DELETE /api/v1/tenants/acme",
	"DELETE /api/v1/organization/members/{id}/mfa",
	"POST /api/v1/organization/members/{id}/offboard",
	"POST /api/v1/organization/members/{id}/erase",
	"GET /api/v1/integrations/jira/webhook-secret",
	"POST /api/v1/integrations/jira/webhook-secret/rotate",
	"GET /api/v1/integrations/github/webhook-secret",
	"POST /api/v1/integrations/github/webhook-secret/rotate",
	"PATCH /api/v1/attachments/storage-config",
	// Widening scope (RFC-054 §6): approving an entry, the settings, and
	// taking an exclusion out of effect.
	"PUT /api/v1/scope/settings",
	"POST /api/v1/scope/targets/{id}/approve",
	"POST /api/v1/scope/exclusions/{id}/deactivate",
	"POST /api/v1/scope/exclusions/bulk/delete",
	"DELETE /api/v1/scope/exclusions/{id}",
	// A seed authorizes every name under it: adding one or turning its
	// discovery on widens scope.
	"POST /api/v1/easm/seeds",
	"PATCH /api/v1/easm/seeds/{id}",
	"POST /api/v1/sensors",
	"POST /api/v1/sensors/{id}/regenerate-key",
	"POST /api/v1/credentials/{id}/reveal",
}

func TestStepUpRoutes_RequireRecentAuth(t *testing.T) {
	tn, err := tenant.NewTenant("Acme", "acme", shared.NewID().String())
	if err != nil {
		t.Fatal(err)
	}
	u, err := userdom.NewProvisionedLocalUser("owner@acme.test", "Owner")
	if err != nil {
		t.Fatal(err)
	}
	userID := u.ID()
	m, err := tenant.NewMembership(userID, tn.ID(), tenant.RoleOwner, nil)
	if err != nil {
		t.Fatal(err)
	}
	gen := jwt.NewGenerator(jwt.TokenConfig{Secret: "step-up-route-test-secret-0123456789abcdef", Issuer: "test",
		AccessTokenDuration: time.Hour, RefreshTokenDuration: time.Hour})
	tok, err := gen.GenerateTenantScopedAccessToken(userID.String(), "owner@acme.test", "Owner", shared.NewID().String(),
		jwt.TenantMembership{TenantID: tn.ID().String(), TenantSlug: "acme", Role: "owner"}, true, 0, "password")
	if err != nil {
		t.Fatal(err)
	}
	auth := middleware.UnifiedAuth(middleware.UnifiedAuthConfig{Provider: config.AuthProviderLocal, LocalValidator: gen})
	setUser := func(next http.Handler) http.Handler { // the tenant chain's user lookup
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), middleware.LocalUserKey, u)))
		})
	}

	for _, tc := range []struct {
		name    string
		checker middleware.RecentAuthChecker
		want    string // "" = reaches the handler
	}{
		{"never authenticated in the window", steppedUpAt(time.Now().Add(-11 * time.Minute)), string(middleware.CodeStepUpRequired)},
		{"inside the window", steppedUpAt(time.Now().Add(-9 * time.Minute)), ""},
		{"no checker wired", nil, string(middleware.CodeStepUpUnavailable)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saved := []Middleware{csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware,
				permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware}
			t.Cleanup(func() {
				csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware = saved[0], saved[1], saved[2]
				permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware = saved[3], saved[4], saved[5]
			})
			csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware = nil, nil, nil
			permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware = nil, nil, nil
			withStepUpChecker(t, tc.checker)

			router := infrahttp.NewChiRouter()
			registerAPIKeyRoutes(router, &handler.APIKeyHandler{}, auth, nil)
			registerSCIMRoutes(router, nil, &handler.SCIMTokenHandler{}, nil, auth, nil)
			registerAuditRoutes(router, &handler.AuditHandler{}, auth, nil)
			registerCIRoutes(router, &handler.CIAdminHandler{}, nil, auth, nil, chain(), nil, logger.NewNop())
			registerTenantRoutes(router, &handler.TenantHandler{}, chain(auth, setUser), nil, routeTenantRepo{t: tn}, routeMembers{m: m}, nil, &handler.SSOChangeHandler{})
			registerOrganizationMemberRoutes(router, &handler.LocalAuthHandler{}, &handler.TenantHandler{}, auth, nil)
			registerIntegrationRoutes(router, &handler.IntegrationHandler{}, nil, nil, auth, nil, chain())
			registerAttachmentRoutes(router, &handler.AttachmentHandler{}, auth, nil)
			registerScopeRoutes(router, &handler.ScopeHandler{}, auth, nil, chain())
			registerEASMSeedRoutes(router, &handler.EASMSeedHandler{}, auth, nil, chain())
			registerSensorManagementRoutes(router, &handler.SensorHandler{}, nil, nil, auth, nil)
			registerCredentialRoutes(router, &handler.CredentialImportHandler{}, auth, nil, chain())
			mux := router.(interface{ Handler() http.Handler }).Handler()

			for _, route := range stepUpRoutes {
				method, path, _ := strings.Cut(route, " ")
				path = strings.ReplaceAll(path, "{id}", shared.NewID().String())
				code, body := func() (code int, body string) {
					defer func() {
						if recover() != nil {
							code = reachedHandler // a zero handler panics on its nil service
						}
					}()
					req := httptest.NewRequest(method, path, strings.NewReader("{}"))
					req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
					rec := httptest.NewRecorder()
					mux.ServeHTTP(rec, req)
					return rec.Code, rec.Body.String()
				}()
				var e struct {
					Code string `json:"code"`
				}
				_ = json.Unmarshal([]byte(body), &e)
				if code == http.StatusNotFound || code == http.StatusMethodNotAllowed {
					t.Errorf("%s: %d from the router (route not registered)", route, code)
					continue
				}
				if tc.want == "" {
					if code == http.StatusForbidden && strings.HasPrefix(e.Code, "STEP_UP") {
						t.Errorf("%s: refused with %s inside the window", route, e.Code)
					}
					continue
				}
				if code != http.StatusForbidden || e.Code != tc.want {
					t.Errorf("%s: got %d %q, want 403 %s", route, code, e.Code, tc.want)
				}
			}
		})
	}
}

func chain(mws ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		for i := len(mws) - 1; i >= 0; i-- {
			next = mws[i](next)
		}
		return next
	}
}
