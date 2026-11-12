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
	"POST /api/v1/tenants/{tenant}/members":            "added any existing account without its consent; an invitation is the only way in",
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
	// Issue #970: no caller in the web, e2e, sdk-go, sensor, ctis, CLI, MCP
	// tools or docs. Each extra read path is one more place data scope must
	// be re-applied, and duplicate writes carried their own gates.
	"GET /api/v1/services":                        "services are read through their asset: GET /api/v1/assets/{id}/services",
	"GET /api/v1/services/public":                 "GET /api/v1/assets/{id}/services",
	"GET /api/v1/services/stats":                  "dead",
	"GET /api/v1/services/{id}":                   "GET /api/v1/assets/{id}/services",
	"PUT /api/v1/services/{id}":                   "dead: services are written by discovery",
	"DELETE /api/v1/services/{id}":                "dead: services are written by discovery",
	"GET /api/v1/state-history":                   "the What changed views and GET /api/v1/assets/{id}/state-history",
	"GET /api/v1/state-history/{id}":              "dead",
	"GET /api/v1/state-history/stats":             "GET /api/v1/state-history/counts",
	"GET /api/v1/state-history/timeline":          "dead",
	"GET /api/v1/state-history/compliance":        "dead",
	"GET /api/v1/relationships/usage-stats":       "dead",
	"GET /api/v1/finding-sources/categories":      "GET /api/v1/finding-sources (each source carries its category)",
	"GET /api/v1/finding-sources/categories/{id}": "GET /api/v1/finding-sources",
	"GET /api/v1/finding-sources/code/{code}":     "GET /api/v1/finding-sources",
	"GET /api/v1/finding-sources/{id}":            "GET /api/v1/finding-sources",
	"PATCH /api/v1/findings/{id}/triage":          "duplicate of PATCH /api/v1/findings/{id}/status (confirmed) under another gate",
	"GET /api/v1/attachments/{id}/meta":           "dead: GET /api/v1/attachments lists the metadata",
	"GET /api/v1/commands/{id}":                   "dead: GET /api/v1/commands lists, GET /api/v1/commands/{id}/logs reads the log",
	"POST /api/v1/commands/{id}/cancel":           "a scan run is canceled as a whole: POST /api/v1/scan-runs/{id}/cancel",
	"DELETE /api/v1/commands/{id}":                "dead (sensors:commands:delete removed with it)",
	"GET /api/v1/auth/oauth/providers":            "GET /api/v1/auth/providers",
	// A partial update is PATCH; the web console moved with this change.
	"PUT /api/v1/organization/settings/finding-approvals": "PATCH /api/v1/organization/settings/finding-approvals (same body, same gate)",
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

	// Direct add of an existing account by user id is gone (consent comes
	// from an invitation); listing the members on the same path still works.
	if code := serve(http.MethodPost, "/api/v1/tenants/acme/members"); code != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/v1/tenants/acme/members: got %d, want 405", code)
	}
	if code := serve(http.MethodGet, "/api/v1/tenants/acme/members"); code == http.StatusNotFound || code == http.StatusMethodNotAllowed {
		t.Errorf("GET /api/v1/tenants/acme/members: got %d from the router, want the handler", code)
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

// The issue #970 removals: an administrator with every permission gets 404
// or 405, while the sibling routes that stay still reach their handlers.
func TestRemovedRoutes_Issue970UnusedRoutesAreGone(t *testing.T) {
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
	pass := func(next http.Handler) http.Handler { return next }
	router := infrahttp.NewChiRouter()
	registerAssetServiceRoutes(router, &handler.AssetServiceHandler{}, auth, nil)
	registerAssetStateHistoryRoutes(router, &handler.AssetStateHistoryHandler{}, auth, nil)
	registerAssetRelationshipRoutes(router, &handler.AssetRelationshipHandler{}, auth, nil, pass)
	registerFindingSourceRoutes(router, &handler.FindingSourceHandler{}, auth, nil)
	registerVulnerabilityRoutes(router, &handler.VulnerabilityHandler{}, &handler.FindingActionsHandler{},
		&handler.JiraWebhookHandler{}, nil, auth, nil)
	registerAttachmentRoutes(router, &handler.AttachmentHandler{}, auth, nil)
	registerCommandRoutes(router, &handler.CommandHandler{}, auth, nil)
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
		{http.MethodGet, "/api/v1/services"},
		{http.MethodGet, "/api/v1/services/public"},
		{http.MethodGet, "/api/v1/services/stats"},
		{http.MethodGet, "/api/v1/services/" + id},
		{http.MethodPut, "/api/v1/services/" + id},
		{http.MethodDelete, "/api/v1/services/" + id},
		{http.MethodGet, "/api/v1/state-history"},
		{http.MethodGet, "/api/v1/state-history/" + id},
		{http.MethodGet, "/api/v1/state-history/stats"},
		{http.MethodGet, "/api/v1/state-history/timeline"},
		{http.MethodGet, "/api/v1/state-history/compliance"},
		{http.MethodGet, "/api/v1/relationships/usage-stats"},
		{http.MethodGet, "/api/v1/finding-sources/categories"},
		{http.MethodGet, "/api/v1/finding-sources/categories/" + id},
		{http.MethodGet, "/api/v1/finding-sources/code/nuclei"},
		{http.MethodGet, "/api/v1/finding-sources/" + id},
		{http.MethodPatch, "/api/v1/findings/" + id + "/triage"},
		{http.MethodGet, "/api/v1/attachments/" + id + "/meta"},
		{http.MethodGet, "/api/v1/commands/" + id},
		{http.MethodPost, "/api/v1/commands/" + id + "/cancel"},
		{http.MethodDelete, "/api/v1/commands/" + id},
	} {
		code := serve(tc.method, tc.path)
		// GET /relationships/usage-stats now matches /relationships/{id}:
		// that handler treats "usage-stats" as an id, never as the stats.
		if tc.path == "/api/v1/relationships/usage-stats" && code == reachedHandler {
			continue
		}
		if code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: got %d, want 404 or 405", tc.method, tc.path, code)
		}
	}
	// The routes that stay still route, so the 404/405 above is the removal.
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/assets/" + id + "/services"},
		{http.MethodGet, "/api/v1/assets/" + id + "/state-history"},
		{http.MethodGet, "/api/v1/state-history/counts"},
		{http.MethodGet, "/api/v1/finding-sources"},
		{http.MethodPatch, "/api/v1/findings/" + id + "/severity"},
		{http.MethodPatch, "/api/v1/findings/" + id + "/status"},
		{http.MethodPatch, "/api/v1/findings/" + id + "/classify"},
		{http.MethodPut, "/api/v1/findings/" + id + "/tags"},
		{http.MethodGet, "/api/v1/commands"},
	} {
		if code := serve(tc.method, tc.path); code != reachedHandler {
			t.Errorf("%s %s: got %d, want the handler", tc.method, tc.path, code)
		}
	}
}

// PUT on the finding approval settings is gone: an owner with every
// permission and a recent re-authentication gets 405 (the path keeps GET and
// PATCH), and PATCH still reaches the handler.
func TestRemovedRoutes_FindingApprovalSettingsPutIsGone(t *testing.T) {
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
	vh := &handler.VulnerabilityHandler{}
	vh.SetFindingApprovalSettings(stubApprovalSettings{})
	registerVulnerabilityRoutes(router, vh, nil, nil, nil, auth, nil)
	mux := router.(interface{ Handler() http.Handler }).Handler()

	serve := func(method string) (code int) {
		defer func() {
			if recover() != nil {
				code = reachedHandler
			}
		}()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, "/api/v1/organization/settings/finding-approvals/", strings.NewReader(`{"accept_approval":"all"}`)))
		return rec.Code
	}
	if code := serve(http.MethodPut); code != http.StatusMethodNotAllowed {
		t.Errorf("PUT: got %d, want 405", code)
	}
	if code := serve(http.MethodPatch); code == http.StatusNotFound || code == http.StatusMethodNotAllowed {
		t.Errorf("PATCH: got %d, want the handler", code)
	}
}
