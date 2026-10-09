package routes

// Removed routes stay removed (research route audit, invariant I13). Each
// entry is an operation that was deliberately deleted; the static check fails
// if any route file registers it again, whatever the parameter names, and the
// runtime checks prove the router answers 404 (no such path) or 405 (other
// methods remain on the path) instead of reaching a handler.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/tools/lint/openapicontract"
)

// removedRoutes: "METHOD /path" (parameter names do not matter) and why.
var removedRoutes = map[string]string{
	"DELETE /api/v1/tenants/{tenant}/members/{userId}": "offboarding without step-up; POST /api/v1/organization/members/{member_id}/offboard is the one route",
	"GET /api/v1/dashboard/stats/global":               "summed every organization in the token, skipping the other organizations' IP allowlist, SSO, modules and data scope",
	"POST /api/v1/audit-logs/rebaseline":               "the owner could re-sign the chain that guards against them; the admin console keeps the rebaseline",
	// One capability resource: /capabilities with filters and include=usage.
	"GET /api/v1/capabilities/all":                    "the list with per_page (capped at 100)",
	"GET /api/v1/capabilities/by-category/{category}": "the list with category=",
	"POST /api/v1/capabilities/usage-stats":           "the list with include=usage",
	"GET /api/v1/capabilities/{id}/usage-stats":       "GET /api/v1/capabilities/{id}?include=usage",
	"POST /api/v1/custom-capabilities":                "POST /api/v1/capabilities",
	"PUT /api/v1/custom-capabilities/{id}":            "PUT /api/v1/capabilities/{id}",
	"DELETE /api/v1/custom-capabilities/{id}":         "DELETE /api/v1/capabilities/{id}",
	// Tombstones that only answered 403: the shared catalogs are written by
	// the platform operator (admin console), never by an organization.
	"POST /api/v1/vulnerabilities":             "refusal stub (403); the shared CVE catalog has no tenant writes",
	"PUT /api/v1/vulnerabilities/{id}":         "refusal stub (403)",
	"DELETE /api/v1/vulnerabilities/{id}":      "refusal stub (403)",
	"POST /api/v1/threat-intel/sync":           "refusal stub (403); feeds sync from /api/v1/admin/threat-intel",
	"PATCH /api/v1/threat-intel/sync/{source}": "refusal stub (403)",
	// No caller in the web, e2e, sdk-go, sensor, scripts or public docs.
	"POST /api/v1/findings/{id}/link-ticket":             "dead: tickets are created with create-ticket",
	"DELETE /api/v1/findings/{id}/link-ticket":           "dead",
	"GET /api/v1/findings/analytics/sources":             "dead",
	"PATCH /api/v1/tenants/{tenant}/settings/branch":     "dead: no screen",
	"POST /api/v1/assets/import/kubernetes":              "dead: only the CSV import is used",
	"POST /api/v1/integrations/{id}/import-repositories": "dead: repositories import through the integration sync",
	"GET /api/v1/asset-types/categories":                 "deprecated alias without caller; GET /api/v1/asset-types is the registry",
	"GET /api/v1/asset-types/categories/{categoryId}":    "deprecated alias without caller",
}

func TestRemovedRoutes_NotRegistered(t *testing.T) {
	routes, err := openapicontract.Routes(".")
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) < 100 {
		t.Fatalf("parsed only %d routes: the walker is broken, not the code", len(routes))
	}
	for op, why := range removedRoutes {
		method, path, ok := strings.Cut(op, " ")
		if !ok {
			t.Fatalf("bad entry %q", op)
		}
		want := openapicontract.Op{Method: method, Path: openapicontract.NormalizePath(path)}
		if pos, found := routes[want]; found {
			t.Errorf("%s is registered again at %s; it was removed: %s", op, pos, why)
		}
	}
}

// An owner of the organization (every permission) gets 405 on the removed
// DELETE: the path keeps PATCH, the DELETE reaches no handler.
func TestRemovedRoutes_TenantMemberDeleteIsGone(t *testing.T) {
	tn, err := tenant.NewTenant("Acme", "acme", shared.NewID().String())
	if err != nil {
		t.Fatal(err)
	}
	u, err := userdom.NewProvisionedLocalUser("owner@acme.test", "Owner")
	if err != nil {
		t.Fatal(err)
	}
	m, err := tenant.NewMembership(u.ID(), tn.ID(), tenant.RoleOwner, nil)
	if err != nil {
		t.Fatal(err)
	}
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), middleware.LocalUserKey, u)))
		})
	}
	router := infrahttp.NewChiRouter()
	registerTenantRoutes(router, &handler.TenantHandler{}, auth, nil, routeTenantRepo{t: tn}, routeMembers{m: m}, nil, nil)
	mux := router.(interface{ Handler() http.Handler }).Handler()

	serve := func(method, path string) (code int) {
		defer func() {
			if recover() != nil {
				code = reachedHandler
			}
		}()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec.Code
	}

	path := "/api/v1/tenants/acme/members/" + shared.NewID().String()
	if code := serve(http.MethodDelete, path); code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE %s: got %d, want 405", path, code)
	}
	// The path itself still routes (PATCH changes the role), so the 405 is
	// the router's answer for the removed method, not a missing group.
	if code := serve(http.MethodPatch, path); code == http.StatusNotFound || code == http.StatusMethodNotAllowed {
		t.Errorf("PATCH %s: got %d from the router, want the handler", path, code)
	}
}

// An administrator with every permission gets 404 or 405 on the removed
// dashboard and audit routes, never a handler.
func TestRemovedRoutes_CrossTenantStatsAndTenantRebaselineAreGone(t *testing.T) {
	withStepUpChecker(t, alwaysSteppedUp{})
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), middleware.IsAdminKey, true)
			ctx = context.WithValue(ctx, middleware.TenantIDKey, shared.NewID().String())
			ctx = context.WithValue(ctx, middleware.UserIDKey, shared.NewID().String())
			ctx = context.WithValue(ctx, middleware.SessionIDKey, "removed-routes")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	router := infrahttp.NewChiRouter()
	registerDashboardRoutes(router, &handler.DashboardHandler{}, auth, nil, logger.NewNop())
	registerAuditRoutes(router, &handler.AuditHandler{}, auth, nil)
	mux := router.(interface{ Handler() http.Handler }).Handler()

	serve := func(method, path string) (code int) {
		defer func() {
			if recover() != nil {
				code = reachedHandler
			}
		}()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader("{}")))
		return rec.Code
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/dashboard/stats/global"},
		{http.MethodPost, "/api/v1/audit-logs/rebaseline"},
	} {
		if code := serve(tc.method, tc.path); code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: got %d, want 404 or 405", tc.method, tc.path, code)
		}
	}
	// The sibling routes still route, so the 404/405 above is the removal.
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/dashboard/stats"},
		{http.MethodGet, "/api/v1/audit-logs/verify"},
	} {
		if code := serve(tc.method, tc.path); code != reachedHandler {
			t.Errorf("%s %s: got %d, want the handler", tc.method, tc.path, code)
		}
	}
}

// The shared-catalog tombstones and the dead finding, settings, import and
// category routes: an administrator with every permission gets 404 or 405.
func TestRemovedRoutes_TombstonesAndDeadRoutesAreGone(t *testing.T) {
	withStepUpChecker(t, alwaysSteppedUp{})
	tn, err := tenant.NewTenant("Acme", "acme", shared.NewID().String())
	if err != nil {
		t.Fatal(err)
	}
	u, err := userdom.NewProvisionedLocalUser("owner@acme.test", "Owner")
	if err != nil {
		t.Fatal(err)
	}
	m, err := tenant.NewMembership(u.ID(), tn.ID(), tenant.RoleOwner, nil)
	if err != nil {
		t.Fatal(err)
	}
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), middleware.IsAdminKey, true)
			ctx = context.WithValue(ctx, middleware.TenantIDKey, tn.ID().String())
			ctx = context.WithValue(ctx, middleware.UserIDKey, u.ID().String())
			ctx = context.WithValue(ctx, middleware.SessionIDKey, "removed-routes")
			ctx = context.WithValue(ctx, middleware.LocalUserKey, u)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	router := infrahttp.NewChiRouter()
	registerVulnerabilityRoutes(router, &handler.VulnerabilityHandler{}, &handler.FindingActionsHandler{},
		&handler.JiraWebhookHandler{}, nil, auth, nil)
	registerThreatIntelRoutes(router, &handler.ThreatIntelHandler{}, auth, nil)
	registerTenantRoutes(router, &handler.TenantHandler{}, auth, nil, routeTenantRepo{t: tn}, routeMembers{m: m}, nil, nil)
	mux := router.(interface{ Handler() http.Handler }).Handler()

	serve := func(method, path string) (code int) {
		defer func() {
			if recover() != nil {
				code = reachedHandler
			}
		}()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader("{}")))
		return rec.Code
	}
	id := shared.NewID().String()
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/vulnerabilities"},
		{http.MethodPut, "/api/v1/vulnerabilities/" + id},
		{http.MethodDelete, "/api/v1/vulnerabilities/" + id},
		{http.MethodPost, "/api/v1/threat-intel/sync"},
		{http.MethodPatch, "/api/v1/threat-intel/sync/epss"},
		{http.MethodPost, "/api/v1/findings/" + id + "/link-ticket"},
		{http.MethodDelete, "/api/v1/findings/" + id + "/link-ticket"},
		{http.MethodGet, "/api/v1/findings/analytics/sources"},
		{http.MethodPatch, "/api/v1/tenants/acme/settings/branch"},
	} {
		if code := serve(tc.method, tc.path); code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: got %d, want 404 or 405", tc.method, tc.path, code)
		}
	}
	// The reads on the same paths still route.
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/vulnerabilities/" + id},
		{http.MethodGet, "/api/v1/threat-intel/sync"},
	} {
		if code := serve(tc.method, tc.path); code != reachedHandler {
			t.Errorf("%s %s: got %d, want the handler", tc.method, tc.path, code)
		}
	}
}
