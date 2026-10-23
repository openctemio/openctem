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

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
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

// stubCISettings answers the CI settings routes so that reaching the handler
// is not mistaken for an unregistered route.
type stubCISettings struct{}

func (stubCISettings) GetSettings(context.Context, shared.ID) (cirunapp.Settings, error) {
	return cirunapp.Settings{}, nil
}

func (stubCISettings) UpdateSettings(_ context.Context, _ shared.ID, in cirunapp.Settings, _ cirunapp.Actor) (cirunapp.Settings, error) {
	return in, nil
}

// stepUpRoutes is every route that requires step-up. Adding requireStepUp()
// to a route means adding it here.
var stepUpRoutes = []string{
	"POST /api/v1/api-keys",
	"DELETE /api/v1/api-keys/{id}",
	"POST /api/v1/scim-tokens",
	"POST /api/v1/ci/gate-overrides",
	// CI trust decides who may send results: creating or changing it, and
	// accepting CI sensor keys again, grant upload rights.
	"PUT /api/v1/ci/settings",
	"POST /api/v1/ci/trust-configs",
	"PUT /api/v1/ci/trust-configs/{id}",
	// Binding a code-host app installation or a GitLab group token decides
	// which organization posts the gate for the account's repositories.
	"POST /api/v1/ci/scm-apps/github/installations",
	"POST /api/v1/ci/scm-apps/gitlab-connections",
	"PATCH /api/v1/tenants/acme/settings/security",
	// Risk scoring settings decide every asset's risk band and, with the
	// ownership floor, finding priorities (docs/architecture/scoring-versions.md).
	"PATCH /api/v1/tenants/acme/settings/risk-scoring",
	// Module toggles change what the organization runs and exposes.
	"PATCH /api/v1/tenants/acme/settings/modules",
	"POST /api/v1/tenants/acme/settings/modules/reset",
	"POST /api/v1/tenants/acme/settings/modules/presets/vm/apply",
	// Stored secrets authenticate the organization to outside systems.
	"POST /api/v1/secret-store",
	"PUT /api/v1/secret-store/{id}",
	"POST /api/v1/secret-store/{id}/rotate",
	"DELETE /api/v1/secret-store/{id}",
	// Turning AI triage on lets finding content go to the AI provider.
	"PUT /api/v1/organization/settings/ai",
	"POST /api/v1/tenants/acme/settings/sso/changes/{id}/approve",
	// A domain's sign-up policy decides who may join and who must use SSO.
	"PUT /api/v1/organization/settings/domains/{id}/signup-policy",
	"DELETE /api/v1/tenants/acme",
	// Deleting one's own account (RFC-104).
	"DELETE /api/v1/me/account",
	"POST /api/v1/organization/leave",
	"DELETE /api/v1/organization/members/{id}/mfa",
	"POST /api/v1/organization/members/{id}/offboard",
	"POST /api/v1/organization/members/{id}/erase",
	// Ownership transfer: the owner asks, the member asked accepts.
	"POST /api/v1/organization/ownership-transfer",
	"POST /api/v1/organization/ownership-transfer/approve",
	// Connecting, changing or removing an integration decides where data and
	// credentials go.
	"POST /api/v1/integrations",
	"POST /api/v1/integrations/notifications",
	"PUT /api/v1/integrations/{id}",
	"DELETE /api/v1/integrations/{id}",
	"POST /api/v1/integrations/{id}/disable",
	"POST /api/v1/integrations/{id}/enable",
	"PUT /api/v1/integrations/{id}/notification",
	// The group mapping decides which role a directory group's members get.
	"PUT /api/v1/scim-tokens/group-mappings",
	"POST /api/v1/scim-tokens/{id}/rotate",
	"POST /api/v1/integrations/{id}/jira-webhook/secret/rotate",
	"PUT /api/v1/integrations/{id}/jira-webhook/secret",
	"POST /api/v1/integrations/{id}/github-webhook/secret/rotate",
	"POST /api/v1/integrations/{id}/signing-secret/rotate",
	// A published ticket mapping decides what leaves for the tracker.
	"POST /api/v1/integrations/ticket-mappings/{id}/publish",
	"POST /api/v1/integrations/ticket-mappings/{id}/dry-run",
	// Deleting a profile sends the destination back to the built-in fields.
	"DELETE /api/v1/integrations/ticket-mappings/{id}",
	"PATCH /api/v1/attachments/storage-config",
	// Widening scope (RFC-054 §6): approving an entry, the settings, and
	// taking an exclusion out of effect.
	"PUT /api/v1/scope/settings",
	"PUT /api/v1/scope/settings/intrusive",
	// Scan approval governance (RFC-073): loosening it is the guarded direction.
	"PUT /api/v1/organization/settings/scan-governance/mode",
	"PUT /api/v1/organization/settings/scan-governance/rules",
	"POST /api/v1/scans/{id}/emergency-run",
	"POST /api/v1/scope/targets/{id}/approve",
	"POST /api/v1/scope/exclusions/{id}/deactivate",
	"POST /api/v1/scope/exclusions/bulk/delete",
	"DELETE /api/v1/scope/exclusions/{id}",
	// Bug-bounty programs (RFC-065): the attestation that puts a
	// program's entries into effect.
	"POST /api/v1/programs",
	"PUT /api/v1/programs/{id}/scope",
	"POST /api/v1/programs/{id}/reactivate",
	"PUT /api/v1/programs/{id}/source",
	"POST /api/v1/programs/{id}/pending/apply",
	// Widening who receives a private program's events (RFC-065 §15.4).
	"PUT /api/v1/programs/{id}/notification-channels/{id}",
	"PUT /api/v1/programs/{id}/org-channels",
	// Approving a custom template version for sensors (RFC-040 §11.5).
	"POST /api/v1/scanner-templates/{id}/approve",
	// Approving an intrusive retest check of a finding.
	"POST /api/v1/findings/{id}/retest-check/approve",
	"POST /api/v1/sensors",
	"POST /api/v1/sensors/{id}/regenerate-key",
	"POST /api/v1/credentials/{id}/reveal",
	// A published finding lifecycle decides which status moves need what
	// (RFC-110).
	"POST /api/v1/lifecycles/{id}/versions/1/publish",
	// Renaming or archiving a scheme and archiving a sub-status change what
	// the organization's moves mean as much as publishing does.
	"PATCH /api/v1/lifecycles/{id}",
	"DELETE /api/v1/lifecycles/{id}",
	"DELETE /api/v1/lifecycle-sub-statuses/{id}",
	// A priority rule re-classes findings across the tenant, down to the
	// platform floors (docs/architecture/priority-explainability.md).
	"POST /api/v1/priority-rules",
	"PUT /api/v1/priority-rules/{id}",
	"DELETE /api/v1/priority-rules/{id}",
	// Decisions that close risk (research 225 S2): approving a false-positive
	// or acceptance request (single and group), approving a severity change,
	// deleting a finding, and a bulk move to a closing status. Reject and
	// cancel stay without it.
	"POST /api/v1/approvals/{id}/approve",
	"POST /api/v1/approvals/batches/{id}/approve",
	"POST /api/v1/findings/{id}/severity-requests/{id}/approve",
	"DELETE /api/v1/findings/{id}",
	"POST /api/v1/findings/bulk/status",
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
			ciAdmin := &handler.CIAdminHandler{}
			ciAdmin.SetSettingsService(stubCISettings{})
			registerCIRoutes(router, ciAdmin, nil, auth, nil, chain(), nil, logger.NewNop())
			registerSCMAppRoutes(router, &handler.SCMAppHandler{}, auth, nil, chain(), logger.NewNop())
			registerTenantRoutes(router, &handler.TenantHandler{}, chain(auth, setUser), nil, routeTenantRepo{t: tn}, routeMembers{m: m}, nil, &handler.SSOChangeHandler{})
			registerOrganizationMemberRoutes(router, &handler.LocalAuthHandler{}, &handler.TenantHandler{}, auth, nil)
			registerAISettingsRoutes(router, &handler.AISettingsHandler{}, auth, nil)
			registerUserRoutes(router, &handler.UserHandler{}, nil, auth, nil, config.AuthProviderLocal)
			registerIntegrationRoutes(router, &handler.IntegrationHandler{}, nil, nil, auth, nil, chain(), nil, nil, &handler.TicketMappingHandler{})
			registerAttachmentRoutes(router, &handler.AttachmentHandler{}, auth, nil)
			registerScopeRoutes(router, &handler.ScopeHandler{}, auth, nil, chain())
			registerProgramRoutes(router, &handler.BountyProgramHandler{}, auth, nil, chain())
			registerScannerTemplateRoutes(router, &handler.ScannerTemplateHandler{}, auth, nil, chain())
			registerVulnerabilityRoutes(router, &handler.VulnerabilityHandler{}, nil, nil, nil, auth, nil)
			registerFindingRetestCheckRoutes(router, &handler.FindingRetestCheckHandler{}, auth, nil)
			registerSensorManagementRoutes(router, &handler.SensorHandler{}, nil, nil, auth, nil)
			registerCredentialRoutes(router, &handler.CredentialImportHandler{}, auth, nil, chain())
			registerFindingLifecycleRoutes(router, &handler.FindingLifecycleHandler{}, auth, nil)
			registerScanGovernanceRoutes(router, &handler.ScanGovernanceHandler{}, auth, nil)
			registerSecretStoreRoutes(router, &handler.SecretStoreHandler{}, auth, nil)
			registerPriorityRuleRoutes(router, &handler.PriorityRuleHandler{}, auth, nil, chain())
			scanH := &handler.ScanHandler{}
			scanH.SetApprovals(&handler.ScanApprovalHandler{})
			registerScanRoutes(router, scanH, auth, nil, nil)
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

// The bulk status move needs step-up only when it closes findings; reject and
// cancel of an approval never need it.
func TestFindingDecisionStepUp_BulkAndRejectCancel(t *testing.T) {
	stale := steppedUpAt(time.Now().Add(-11 * time.Minute))
	call := func(t *testing.T, checker middleware.RecentAuthChecker, body string) (code int, reached bool) {
		t.Helper()
		withStepUpChecker(t, checker)
		h := requireStepUpWhenClosing()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			b := make([]byte, len(body))
			n, _ := r.Body.Read(b)
			if string(b[:n]) != body {
				t.Errorf("body not restored: %q", b[:n])
			}
			w.WriteHeader(http.StatusOK)
		}))
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req = req.WithContext(context.WithValue(context.WithValue(req.Context(), middleware.UserIDKey, "u1"), middleware.SessionIDKey, "s1"))
		h.ServeHTTP(rec, req)
		return rec.Code, reached
	}
	if _, reached := call(t, stale, `{"status":"in_progress"}`); !reached {
		t.Error("an open-state bulk move must not need step-up")
	}
	// The service lower-cases and trims the status, and the handler's decoder
	// stops after the first JSON value: neither spelling may skip the gate.
	for _, body := range []string{`{"status":"RESOLVED"}`, `{"status":" resolved "}`, `{"status":"resolved"} trailing`,
		`{"status":"in_progress"`, `{"status":5}`, `{"status":"no_such_status"}`} {
		if code, reached := call(t, stale, body); reached || code != http.StatusForbidden {
			t.Errorf("bulk body %s with a stale session: got %d reached=%v, want 403", body, code, reached)
		}
	}
	if _, reached := call(t, stale, `{"status":" In_Progress "}`); !reached {
		t.Error("an open-state bulk move in any spelling must not need step-up")
	}
	for _, st := range []string{"resolved", "false_positive", "accepted", ""} {
		code, reached := call(t, stale, `{"status":"`+st+`"}`)
		if reached || code != http.StatusForbidden {
			t.Errorf("bulk to %q with a stale session: got %d reached=%v, want 403", st, code, reached)
		}
		if _, reached := call(t, alwaysSteppedUp{}, `{"status":"`+st+`"}`); !reached {
			t.Errorf("bulk to %q with a fresh session must reach the handler", st)
		}
	}
	for _, route := range stepUpRoutes {
		if strings.HasSuffix(route, "/reject") || strings.HasSuffix(route, "/cancel") {
			if strings.Contains(route, "/approvals") || strings.Contains(route, "severity-requests") {
				t.Errorf("%s must not require step-up", route)
			}
		}
	}
}
