package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/api/pkg/domain/permission"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/jwt"
	"github.com/openctemio/api/pkg/logger"
)

// Revocation through the permission-sync middleware (audit H2, F9).
//
// H2: an admin demoted to viewer kept the token's admin flag, so every
// Require() and RequireAdmin passed for the rest of the token's life (~15 min).
// F9: a permission removed from a user kept working for GET requests, because
// HasPermission fell back to the token's embedded permission array after the
// fresh set did not contain it.

const (
	revTenant = "11111111-1111-1111-1111-111111111111"
	revUser   = "22222222-2222-2222-2222-222222222222"
)

type fakeVersions struct {
	version   int
	confirmed bool
}

func (f fakeVersions) GetChecked(context.Context, string, string) (int, bool) {
	return f.version, f.confirmed
}

type fakePerms struct {
	perms []string
	err   error
}

func (f fakePerms) GetPermissionsWithFallback(context.Context, string, string) ([]string, error) {
	return f.perms, f.err
}

type fakeRoles struct {
	role  tenant.Role
	err   error
	calls int
}

func (f *fakeRoles) GetMembership(_ context.Context, userID, tenantID shared.ID) (*tenant.Membership, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	m, err := tenant.NewMembership(userID, tenantID, f.role, nil)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// tokenRequest builds the context UnifiedAuth leaves behind for a local token.
func tokenRequest(method string, role string, isAdmin bool, perms []string, pv int) *http.Request {
	claims := &jwt.Claims{
		UserID: revUser, TenantID: revTenant, Role: role,
		Permissions: perms, IsAdmin: isAdmin, PermVersion: pv,
	}
	ctx := context.Background()
	ctx = context.WithValue(ctx, UserIDKey, revUser)
	ctx = context.WithValue(ctx, TenantIDKey, revTenant)
	ctx = context.WithValue(ctx, RoleKey, role)
	ctx = context.WithValue(ctx, PermissionsKey, perms)
	ctx = context.WithValue(ctx, IsAdminKey, isAdmin)
	ctx = context.WithValue(ctx, LocalClaimsKey, claims)
	return httptest.NewRequest(method, "/api/v1/x", nil).WithContext(ctx)
}

func serve(sync func(http.Handler) http.Handler, gate func(http.Handler) http.Handler, req *http.Request) int {
	h := sync(gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func newTestPermSync(v fakeVersions, p fakePerms, roles TeamRoleReader) *PermissionSyncMiddleware {
	return newPermissionSyncMiddleware(v, p, roles, logger.NewNop())
}

// H2: the demoted admin's next request (here a read) loses the admin bypass,
// because a stale token's admin flag and role are re-derived from the database.
func TestPermissionSync_DemotedAdminLosesBypassOnNextRequest(t *testing.T) {
	roles := &fakeRoles{role: tenant.RoleViewer}
	m := newTestPermSync(fakeVersions{version: 2, confirmed: true}, fakePerms{perms: []string{"assets:read"}}, roles)

	if code := serve(m.EnrichPermissions, Require(permission.RolesWrite), tokenRequest(http.MethodGet, "admin", true, nil, 1)); code != http.StatusForbidden {
		t.Fatalf("stale admin token on a roles:write route: %d, want 403", code)
	}
	if code := serve(m.EnrichPermissions, RequireAdmin(), tokenRequest(http.MethodGet, "admin", true, nil, 1)); code != http.StatusForbidden {
		t.Fatalf("stale admin token on RequireAdmin: %d, want 403", code)
	}
	if code := serve(m.EnrichPermissions, RequireOwner(), tokenRequest(http.MethodGet, "owner", true, nil, 1)); code != http.StatusForbidden {
		t.Fatalf("stale owner token on RequireOwner after demotion: %d, want 403", code)
	}
	if code := serve(m.EnrichPermissions, Require(permission.AssetsRead), tokenRequest(http.MethodGet, "admin", true, nil, 1)); code != http.StatusOK {
		t.Fatalf("demoted admin keeps what the viewer role grants: %d, want 200", code)
	}
	// Writes with a stale token are refused outright.
	if code := serve(m.EnrichPermissions, Require(permission.AssetsRead), tokenRequest(http.MethodPost, "admin", true, nil, 1)); code != http.StatusConflict {
		t.Fatalf("stale write: %d, want 409", code)
	}
	if roles.calls == 0 {
		t.Fatal("the team role was not read from the database")
	}
}

// A still-current admin token is trusted without a database read.
func TestPermissionSync_CurrentAdminTokenKeepsBypass(t *testing.T) {
	roles := &fakeRoles{role: tenant.RoleViewer}
	m := newTestPermSync(fakeVersions{version: 1, confirmed: true}, fakePerms{perms: nil}, roles)
	if code := serve(m.EnrichPermissions, RequireAdmin(), tokenRequest(http.MethodGet, "admin", true, nil, 1)); code != http.StatusOK {
		t.Fatalf("current admin token: %d, want 200", code)
	}
	if roles.calls != 0 {
		t.Fatalf("current token caused %d team-role lookups", roles.calls)
	}
}

// A stale token whose team role is still admin keeps admin (a promotion or an
// unrelated role change must not lock an admin out of reads).
func TestPermissionSync_StaleTokenStillAdminInDatabase(t *testing.T) {
	m := newTestPermSync(fakeVersions{version: 3, confirmed: true}, fakePerms{perms: nil}, &fakeRoles{role: tenant.RoleAdmin})
	if code := serve(m.EnrichPermissions, RequireAdmin(), tokenRequest(http.MethodGet, "member", false, nil, 1)); code != http.StatusOK {
		t.Fatalf("stale token of a current admin: %d, want 200", code)
	}
}

// Fail closed: a stale token whose team role cannot be re-derived is refused
// the same way a stale write is.
func TestPermissionSync_StaleAndTeamRoleUnavailable_FailsClosed(t *testing.T) {
	for name, roles := range map[string]TeamRoleReader{
		"lookup error": &fakeRoles{err: errors.New("db down")},
		"no reader":    nil,
	} {
		m := newTestPermSync(fakeVersions{version: 2, confirmed: true}, fakePerms{perms: []string{"assets:read"}}, roles)
		if code := serve(m.EnrichPermissions, Require(permission.AssetsRead), tokenRequest(http.MethodGet, "admin", true, nil, 1)); code != http.StatusConflict {
			t.Fatalf("%s: stale read without a team role: %d, want 409", name, code)
		}
	}
}

// F9: a permission removed from the user stops working for reads on the next
// request, even though the old token still lists it.
func TestPermissionSync_RevokedPermissionDeniedForReads(t *testing.T) {
	stale := newTestPermSync(fakeVersions{version: 8, confirmed: true}, fakePerms{perms: []string{"dashboard:read"}}, &fakeRoles{role: tenant.RoleViewer})
	if code := serve(stale.EnrichPermissions, Require(permission.AssetsRead), tokenRequest(http.MethodGet, "viewer", false, []string{"assets:read"}, 7)); code != http.StatusForbidden {
		t.Fatalf("revoked assets:read on GET with the old token: %d, want 403", code)
	}
	if code := serve(stale.EnrichPermissions, Require(permission.DashboardRead), tokenRequest(http.MethodGet, "viewer", false, []string{"assets:read"}, 7)); code != http.StatusOK {
		t.Fatalf("still-granted dashboard:read: %d, want 200", code)
	}
	// Same when the version is not (yet) confirmed: the fresh set wins.
	unconfirmed := newTestPermSync(fakeVersions{version: 1, confirmed: false}, fakePerms{perms: []string{"dashboard:read"}}, &fakeRoles{role: tenant.RoleViewer})
	if code := serve(unconfirmed.EnrichPermissions, Require(permission.AssetsRead), tokenRequest(http.MethodGet, "viewer", false, []string{"assets:read"}, 1)); code != http.StatusForbidden {
		t.Fatalf("permission absent from the fresh set: %d, want 403", code)
	}
}

// When the fresh permission set cannot be loaded: a current token keeps its
// own permissions (a cache/DB outage is not a revocation), a stale one is
// refused.
func TestPermissionSync_PermissionLookupFailure(t *testing.T) {
	current := newTestPermSync(fakeVersions{version: 1, confirmed: true}, fakePerms{err: errors.New("db down")}, &fakeRoles{role: tenant.RoleViewer})
	if code := serve(current.EnrichPermissions, Require(permission.AssetsRead), tokenRequest(http.MethodGet, "viewer", false, []string{"assets:read"}, 1)); code != http.StatusOK {
		t.Fatalf("current token during a permission lookup outage: %d, want 200", code)
	}
	stale := newTestPermSync(fakeVersions{version: 2, confirmed: true}, fakePerms{err: errors.New("db down")}, &fakeRoles{role: tenant.RoleViewer})
	if code := serve(stale.EnrichPermissions, Require(permission.AssetsRead), tokenRequest(http.MethodGet, "viewer", false, []string{"assets:read"}, 1)); code != http.StatusConflict {
		t.Fatalf("stale token during a permission lookup outage: %d, want 409", code)
	}
}

// Without the sync middleware (routes that do not mount it, OIDC), the token's
// permissions are still honored.
func TestHasPermission_WithoutSyncUsesTokenPermissions(t *testing.T) {
	req := tokenRequest(http.MethodGet, "viewer", false, []string{"assets:read"}, 1)
	if !HasPermission(req.Context(), "assets:read") {
		t.Fatal("token permission not honored without the sync middleware")
	}
}
