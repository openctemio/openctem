package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The /api/v1/tenants/{tenant} routes (members, invitations, security, API,
// data-scope and module settings) take the organization from the URL, not
// from the token, and build their own middleware chain in tenant.go. That
// chain must apply the same per-request controls as the token-tenant chain,
// evaluated for the organization in the URL (RFC-041 §3.2 P1):
//
//   - SSO enforcement: a password session must not administer an
//     organization that requires SSO sign-in, even when the token was minted
//     for another organization the user also belongs to.
//   - The per-user read rate limit.

type ssoByTenant map[string]bool

func (s ssoByTenant) IsSSOEnforced(_ context.Context, tenantID string) (bool, error) {
	return s[tenantID], nil
}

// urlChainFixture registers the tenant routes for one organization ("acme",
// SSO enforced) whose member is an admin, authenticated by a password token
// minted for a different organization the user also belongs to.
func urlChainFixture(t *testing.T, tokenRole string, memberRole tenant.Role) (http.Handler, *tenant.Tenant) {
	t.Helper()
	tn, err := tenant.NewTenant("Acme", "acme", shared.NewID().String())
	if err != nil {
		t.Fatal(err)
	}
	u, err := userdom.NewProvisionedLocalUser("admin@acme.test", "Admin")
	if err != nil {
		t.Fatal(err)
	}
	m, err := tenant.NewMembership(u.ID(), tn.ID(), memberRole, nil)
	if err != nil {
		t.Fatal(err)
	}
	otherTenant := shared.NewID().String()
	claims := &jwt.Claims{UserID: u.ID().String(), TenantID: otherTenant, Role: tokenRole, AuthMethod: "password"}
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), middleware.LocalUserKey, u)
			ctx = context.WithValue(ctx, middleware.LocalClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	prevSSO := ssoEnforcementMiddleware
	ssoEnforcementMiddleware = middleware.NewSSOEnforcementGate(
		ssoByTenant{tn.ID().String(): true, otherTenant: false}, time.Minute, logger.NewNop()).Enforce
	t.Cleanup(func() { ssoEnforcementMiddleware = prevSSO })

	router := infrahttp.NewChiRouter()
	registerTenantRoutes(router, &handler.TenantHandler{}, auth, nil, routeTenantRepo{t: tn}, routeMembers{m: m}, nil, nil, nil)
	return router.(interface{ Handler() http.Handler }).Handler(), tn
}

func serveCode(mux http.Handler, method, path string) (code int) {
	defer func() {
		if recover() != nil {
			code = reachedHandler
		}
	}()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec.Code
}

func TestTenantURLChain_SSOEnforcedForURLOrganization(t *testing.T) {
	for _, tc := range []struct {
		name       string
		tokenRole  string
		memberRole tenant.Role
	}{
		// Admin of the SSO-enforced organization, token minted elsewhere.
		{"admin with a token from another organization", "admin", tenant.RoleAdmin},
		// Owner of ANOTHER organization: the token's owner role must not
		// stand in for the role in the URL organization.
		{"owner elsewhere, admin here", "owner", tenant.RoleAdmin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux, tn := urlChainFixture(t, tc.tokenRole, tc.memberRole)
			for _, p := range []struct{ method, path string }{
				{http.MethodGet, "/api/v1/tenants/acme/settings"},
				{http.MethodPatch, "/api/v1/tenants/acme/settings/security"},
				{http.MethodPost, "/api/v1/tenants/" + tn.ID().String() + "/members"},
			} {
				if got := serveCode(mux, p.method, p.path); got != http.StatusForbidden {
					t.Errorf("%s %s: got %d, want 403 (organization requires SSO sign-in)", p.method, p.path, got)
				}
			}
		})
	}
}

func TestTenantURLChain_OwnerOfURLOrganizationPasses(t *testing.T) {
	// Break-glass: the owner of the URL organization is never locked out.
	mux, _ := urlChainFixture(t, "member", tenant.RoleOwner)
	if got := serveCode(mux, http.MethodGet, "/api/v1/tenants/acme/settings"); got == http.StatusForbidden {
		t.Fatalf("owner of the URL organization: got 403, want the handler")
	}
}

func TestTenantURLChain_AppliesReadRateLimit(t *testing.T) {
	ran := 0
	prev := readRateLimitMiddleware
	readRateLimitMiddleware = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ran++
			next.ServeHTTP(w, r)
		})
	}
	t.Cleanup(func() { readRateLimitMiddleware = prev })

	mux, _ := urlChainFixture(t, "owner", tenant.RoleOwner)
	serveCode(mux, http.MethodGet, "/api/v1/tenants/acme/members")
	if ran != 1 {
		t.Fatalf("read rate limit ran %d times on GET /tenants/{tenant}/members, want 1", ran)
	}
}
