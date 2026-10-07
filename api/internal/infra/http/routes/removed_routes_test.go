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
	"github.com/openctemio/openctem/api/tools/lint/openapicontract"
)

// removedRoutes: "METHOD /path" (parameter names do not matter) and why.
var removedRoutes = map[string]string{
	"DELETE /api/v1/tenants/{tenant}/members/{userId}": "offboarding without step-up; POST /api/v1/organization/members/{member_id}/offboard is the one route",
	// One capability resource: /capabilities with filters and include=usage.
	"GET /api/v1/capabilities/all":                    "the list with per_page (capped at 100)",
	"GET /api/v1/capabilities/by-category/{category}": "the list with category=",
	"POST /api/v1/capabilities/usage-stats":           "the list with include=usage",
	"GET /api/v1/capabilities/{id}/usage-stats":       "GET /api/v1/capabilities/{id}?include=usage",
	"POST /api/v1/custom-capabilities":                "POST /api/v1/capabilities",
	"PUT /api/v1/custom-capabilities/{id}":            "PUT /api/v1/capabilities/{id}",
	"DELETE /api/v1/custom-capabilities/{id}":         "DELETE /api/v1/capabilities/{id}",
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
