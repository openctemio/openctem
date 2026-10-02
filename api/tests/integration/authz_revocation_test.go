package integration

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/infra/redis"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Revocation and setup-link reissue, end to end against Postgres and Redis
// (audit H2, H3, F9, M1).
//
// Redis is used only when REDIS_HOST is set explicitly (CI sets it); the test
// never falls back to a default address.

const (
	revOwnerRole  = "00000000-0000-0000-0000-000000000001"
	revAdminRole  = "00000000-0000-0000-0000-000000000002"
	revMemberRole = "00000000-0000-0000-0000-000000000003"
	revViewerRole = "00000000-0000-0000-0000-000000000004"
)

type revFixture struct {
	t           *testing.T
	ctx         context.Context
	db          *sql.DB
	tenantID    string
	users       []string
	tenants     *postgres.TenantRepository
	permVersion *accesscontrol.PermissionVersionService
	permCache   *accesscontrol.PermissionCacheService
	members     *accesscontrol.MembershipCacheService
	roles       *accesscontrol.RoleService
	tenantSvc   *tenantapp.TenantService
}

func newRevFixture(t *testing.T) *revFixture {
	t.Helper()
	dsn := testdb.URL()
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping revocation DB test")
	}
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		t.Skip("REDIS_HOST not set; skipping revocation test that needs Redis")
	}
	port := 6379
	if p := os.Getenv("REDIS_PORT"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			t.Fatalf("REDIS_PORT: %v", err)
		}
		port = n
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Skipf("database not available: %v", err)
	}
	log := logger.NewNop()
	rc, err := redis.New(&config.RedisConfig{
		Host: host, Port: port, PoolSize: 4, MinIdleConns: 0,
		DialTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second,
		MaxRetries: 1, MinRetryDelay: 10 * time.Millisecond, MaxRetryDelay: 50 * time.Millisecond,
	}, log)
	if err != nil {
		t.Skipf("redis not available: %v", err)
	}

	f := &revFixture{t: t, ctx: context.Background(), db: db, tenantID: uuid.NewString()}
	f.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'Revocation IT', $2)`,
		f.tenantID, "revocation-"+strings.ReplaceAll(f.tenantID[:13], "-", ""))
	t.Cleanup(func() {
		_, _ = db.ExecContext(f.ctx, `DELETE FROM user_roles WHERE tenant_id = $1`, f.tenantID)
		_, _ = db.ExecContext(f.ctx, `DELETE FROM roles WHERE tenant_id = $1`, f.tenantID)
		_, _ = db.ExecContext(f.ctx, `DELETE FROM tenant_members WHERE tenant_id = $1`, f.tenantID)
		if len(f.users) > 0 {
			_, _ = db.ExecContext(f.ctx, `DELETE FROM users WHERE id = ANY($1)`, "{"+strings.Join(f.users, ",")+"}")
		}
		_, _ = db.ExecContext(f.ctx, `DELETE FROM tenants WHERE id = $1`, f.tenantID)
		_ = db.Close()
		_ = rc.Close()
	})

	pg := &postgres.DB{DB: db}
	f.tenants = postgres.NewTenantRepository(pg)
	roleRepo := postgres.NewRoleRepository(pg)
	f.permVersion = accesscontrol.NewPermissionVersionService(rc, log)
	f.permCache, err = accesscontrol.NewPermissionCacheService(rc, roleRepo, f.permVersion, log)
	if err != nil {
		t.Fatal(err)
	}
	f.members, err = accesscontrol.NewMembershipCacheService(rc, f.tenants, log)
	if err != nil {
		t.Fatal(err)
	}
	f.roles = accesscontrol.NewRoleService(roleRepo, postgres.NewPermissionRepository(pg), log,
		accesscontrol.WithRolePermissionVersionService(f.permVersion),
		accesscontrol.WithRolePermissionCacheService(f.permCache),
		accesscontrol.WithRoleMembershipReader(f.members),
		accesscontrol.WithRoleMembershipCacheInvalidator(f.members),
	)
	f.tenantSvc = tenantapp.NewTenantService(f.tenants, log)
	f.tenantSvc.SetPermissionServices(f.permCache, f.permVersion)
	f.tenantSvc.SetMembershipCache(f.members)
	return f
}

func (f *revFixture) exec(q string, args ...any) {
	f.t.Helper()
	if _, err := f.db.ExecContext(f.ctx, q, args...); err != nil {
		f.t.Fatalf("%s: %v", q, err)
	}
}

// member adds a user with membership label `label` (the trigger grants the
// matching system role). pending users have no password and never signed in.
func (f *revFixture) member(label string, pending bool) string {
	f.t.Helper()
	id := uuid.NewString()
	f.users = append(f.users, id)
	hash := any("x")
	if pending {
		hash = nil
	}
	f.exec(`INSERT INTO users (id, email, name, auth_provider, password_hash) VALUES ($1, $2, 'Revocation IT', 'local', $3)`,
		id, "rev-"+id[:8]+"@it.test", hash)
	f.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, $3)`, id, f.tenantID, label)
	return id
}

func (f *revFixture) membershipID(uid string) string {
	f.t.Helper()
	var id string
	if err := f.db.QueryRowContext(f.ctx, `SELECT id FROM tenant_members WHERE user_id = $1 AND tenant_id = $2`, uid, f.tenantID).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *revFixture) customRole(slug string, perms ...string) string {
	f.t.Helper()
	id := uuid.NewString()
	f.exec(`INSERT INTO roles (id, tenant_id, slug, name, is_system, hierarchy_level) VALUES ($1, $2, $3, $3, FALSE, 10)`, id, f.tenantID, slug)
	for _, p := range perms {
		f.exec(`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)`, id, p)
	}
	return id
}

// token is the request context UnifiedAuth builds from an access token minted
// now: the current team role, admin flag, permissions and permission version.
type revToken struct {
	userID  string
	role    string
	isAdmin bool
	perms   []string
	pv      int
}

func (f *revFixture) mint(uid string) revToken {
	f.t.Helper()
	u, _ := shared.IDFromString(uid)
	tid, _ := shared.IDFromString(f.tenantID)
	m, err := f.tenants.GetMembership(f.ctx, u, tid)
	if err != nil {
		f.t.Fatal(err)
	}
	role := m.Role().String()
	tok := revToken{userID: uid, role: role, isAdmin: role == "owner" || role == "admin",
		pv: f.permVersion.EnsureVersion(f.ctx, f.tenantID, uid)}
	if !tok.isAdmin {
		tok.perms, err = f.roles.GetUserPermissions(f.ctx, f.tenantID, uid)
		if err != nil {
			f.t.Fatal(err)
		}
	}
	return tok
}

// call sends a request with tok through the token-tenant chain's permission
// sync middleware and then gate.
func (f *revFixture) call(tok revToken, method string, gate func(http.Handler) http.Handler) int {
	f.t.Helper()
	sync := middleware.NewPermissionSyncMiddleware(f.permCache, f.permVersion, logger.NewNop()).
		WithTeamRoleReader(f.tenants).EnrichPermissions
	h := sync(gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })))
	claims := &jwt.Claims{UserID: tok.userID, TenantID: f.tenantID, Role: tok.role,
		Permissions: tok.perms, IsAdmin: tok.isAdmin, PermVersion: tok.pv}
	ctx := context.WithValue(f.ctx, middleware.UserIDKey, tok.userID)
	ctx = context.WithValue(ctx, middleware.TenantIDKey, f.tenantID)
	ctx = context.WithValue(ctx, middleware.RoleKey, tok.role)
	ctx = context.WithValue(ctx, middleware.PermissionsKey, tok.perms)
	ctx = context.WithValue(ctx, middleware.IsAdminKey, tok.isAdmin)
	ctx = context.WithValue(ctx, middleware.LocalClaimsKey, claims)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, "/api/v1/x", nil).WithContext(ctx))
	return rec.Code
}

// cachedTeamRole reads the team role through the membership cache that the
// RequireMembership / RequireTeamAdmin gates use.
func (f *revFixture) cachedTeamRole(uid string) string {
	f.t.Helper()
	u, _ := shared.IDFromString(uid)
	tid, _ := shared.IDFromString(f.tenantID)
	m, err := f.members.GetMembership(f.ctx, u, tid)
	if err != nil {
		f.t.Fatal(err)
	}
	return m.Role().String()
}

// H2: an owner demotes an admin to viewer through the member-role endpoint;
// the admin's still-valid token loses the admin bypass on its next request,
// reads included.
func TestRevocation_DemotedAdminLosesBypassOnNextRequest(t *testing.T) {
	f := newRevFixture(t)
	owner := f.member("owner", false)
	admin := f.member("admin", false)
	tok := f.mint(admin)
	if code := f.call(tok, http.MethodGet, middleware.RequireAdmin()); code != http.StatusOK {
		t.Fatalf("admin before demotion: %d", code)
	}

	if _, err := f.tenantSvc.UpdateMemberRole(f.ctx, f.membershipID(admin), tenantapp.UpdateMemberRoleInput{Role: "viewer"},
		auditapp.AuditContext{TenantID: f.tenantID, ActorID: owner}); err != nil {
		t.Fatalf("demote: %v", err)
	}

	if code := f.call(tok, http.MethodGet, middleware.RequireAdmin()); code != http.StatusForbidden {
		t.Fatalf("old admin token on RequireAdmin after demotion: %d, want 403", code)
	}
	if code := f.call(tok, http.MethodGet, middleware.Require(permission.RolesWrite)); code != http.StatusForbidden {
		t.Fatalf("old admin token on roles:write after demotion: %d, want 403", code)
	}
	if code := f.call(tok, http.MethodPost, middleware.Require(permission.APIKeysWrite)); code != http.StatusConflict {
		t.Fatalf("old admin token write after demotion: %d, want 409", code)
	}
	if code := f.call(tok, http.MethodGet, middleware.Require(permission.AssetsRead)); code != http.StatusOK {
		t.Fatalf("demoted admin keeps viewer reads: %d, want 200", code)
	}
	// A fresh token is a plain viewer.
	if fresh := f.mint(admin); fresh.isAdmin || fresh.role != "viewer" {
		t.Fatalf("fresh token after demotion: role=%q admin=%v", fresh.role, fresh.isAdmin)
	}
}

// H3: RBAC role changes drop the cached membership, so the team-admin gates
// see the new role on the next request.
func TestRevocation_RoleChangesInvalidateMembershipCache(t *testing.T) {
	f := newRevFixture(t)
	owner := f.member("owner", false)
	actx := auditapp.AuditContext{TenantID: f.tenantID, ActorID: owner}

	a := f.member("admin", false)
	if got := f.cachedTeamRole(a); got != "admin" {
		t.Fatalf("warm cache: %q", got)
	}
	if err := f.roles.SetUserRoles(f.ctx, accesscontrol.SetUserRolesInput{
		TenantID: f.tenantID, UserID: a, RoleIDs: []string{revViewerRole},
	}, owner, actx); err != nil {
		t.Fatalf("SetUserRoles: %v", err)
	}
	if got := f.cachedTeamRole(a); got != "viewer" {
		t.Fatalf("after SetUserRoles [viewer] the cached team role is %q, want viewer", got)
	}

	b := f.member("admin", false)
	f.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, b, f.tenantID, revMemberRole)
	_ = f.cachedTeamRole(b)
	if err := f.roles.RemoveRole(f.ctx, f.tenantID, b, revAdminRole, actx); err != nil {
		t.Fatalf("RemoveRole: %v", err)
	}
	if got := f.cachedTeamRole(b); got != "member" {
		t.Fatalf("after RemoveRole admin the cached team role is %q, want member", got)
	}

	c := f.member("viewer", false)
	_ = f.cachedTeamRole(c)
	if err := f.roles.AssignRole(f.ctx, accesscontrol.AssignRoleInput{
		TenantID: f.tenantID, UserID: c, RoleID: revAdminRole,
	}, owner, actx); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	if got := f.cachedTeamRole(c); got != "admin" {
		t.Fatalf("after AssignRole admin the cached team role is %q, want admin", got)
	}

	d := f.member("viewer", false)
	_ = f.cachedTeamRole(d)
	if _, err := f.roles.BulkAssignRoleToUsers(f.ctx, accesscontrol.BulkAssignRoleToUsersInput{
		TenantID: f.tenantID, RoleID: revMemberRole, UserIDs: []string{d},
	}, owner, actx); err != nil {
		t.Fatalf("BulkAssignRoleToUsers: %v", err)
	}
	if got := f.cachedTeamRole(d); got != "member" {
		t.Fatalf("after BulkAssign member the cached team role is %q, want member", got)
	}

	// Through the gate itself.
	users := postgres.NewUserRepository(&postgres.DB{DB: f.db})
	uid, _ := shared.IDFromString(a)
	u, err := users.GetByID(f.ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	tid, _ := shared.IDFromString(f.tenantID)
	gate := middleware.RequireMembership(f.members)(middleware.RequireTeamAdmin()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	ctx := context.WithValue(f.ctx, middleware.LocalUserKey, u)
	ctx = context.WithValue(ctx, middleware.TeamIDKey, tid)
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/tenants/x/invitations", nil).WithContext(ctx))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("demoted admin through RequireTeamAdmin: %d, want 403", rec.Code)
	}
}

// F9: a permission removed from a user stops working for reads with the old
// token on the next request.
func TestRevocation_RemovedPermissionStopsReads(t *testing.T) {
	f := newRevFixture(t)
	owner := f.member("owner", false)
	victim := f.member("viewer", false)
	assetsRole := f.customRole("rev-assets", "assets:read", "dashboard:read")
	dashRole := f.customRole("rev-dash", "dashboard:read")
	actx := auditapp.AuditContext{TenantID: f.tenantID, ActorID: owner}
	if err := f.roles.SetUserRoles(f.ctx, accesscontrol.SetUserRolesInput{
		TenantID: f.tenantID, UserID: victim, RoleIDs: []string{assetsRole},
	}, owner, actx); err != nil {
		t.Fatal(err)
	}
	tok := f.mint(victim)
	if code := f.call(tok, http.MethodGet, middleware.Require(permission.AssetsRead)); code != http.StatusOK {
		t.Fatalf("before revocation: %d", code)
	}
	if err := f.roles.SetUserRoles(f.ctx, accesscontrol.SetUserRolesInput{
		TenantID: f.tenantID, UserID: victim, RoleIDs: []string{dashRole},
	}, owner, actx); err != nil {
		t.Fatal(err)
	}
	if code := f.call(tok, http.MethodGet, middleware.Require(permission.AssetsRead)); code != http.StatusForbidden {
		t.Fatalf("old token GET after assets:read was removed: %d, want 403", code)
	}
	if code := f.call(tok, http.MethodGet, middleware.Require(permission.DashboardRead)); code != http.StatusOK {
		t.Fatalf("old token GET on a still-granted permission: %d, want 200", code)
	}
}

// M1: a set-password link for a pending account is a takeover of that account
// before its first sign-in, so it is issued only for a target the caller could
// manage: an owner or admin target needs an owner, and an owner target's token
// never goes to a non-owner. The platform console (no tenant caller) may still
// issue the owner's first link.
func TestRevocation_SetupLinkReissueBoundedByCallerRole(t *testing.T) {
	f := newRevFixture(t)
	owner := f.member("owner", false)
	admin := f.member("admin", false)
	pendingOwner := f.member("owner", true)
	pendingAdmin := f.member("admin", true)
	pendingMember := f.member("member", true)
	pendingCustom := f.member("viewer", true)
	f.exec(`DELETE FROM user_roles WHERE user_id = $1`, pendingCustom)
	f.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, pendingCustom, f.tenantID,
		f.customRole("rev-reveal", "findings:credentials:reveal", "team:delete"))

	pg := &postgres.DB{DB: f.db}
	prov := tenantapp.NewUserProvisioningService(f.tenants, postgres.NewUserRepository(pg), f.roles, nil, nil, logger.NewNop())
	reissue := func(caller, target string) error {
		res, err := prov.ReissueSetupLink(f.ctx, f.tenantID, target, caller, auditapp.AuditContext{TenantID: f.tenantID, ActorID: caller})
		if err == nil && res.SetupToken == "" {
			t.Fatalf("reissue for %s returned no token", target)
		}
		return err
	}
	forbidden := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, shared.ErrForbidden) {
			t.Fatalf("%s: want forbidden, got %v", what, err)
		}
	}
	forbidden("admin -> pending owner", reissue(admin, pendingOwner))
	forbidden("admin -> pending admin", reissue(admin, pendingAdmin))
	forbidden("admin -> pending holder of a role beyond the admin's grants", reissue(admin, pendingCustom))
	if err := reissue(admin, pendingMember); err != nil {
		t.Fatalf("admin -> pending member: %v", err)
	}
	if err := reissue(owner, pendingAdmin); err != nil {
		t.Fatalf("owner -> pending admin: %v", err)
	}
	if err := reissue(owner, pendingOwner); err != nil {
		t.Fatalf("owner -> pending owner: %v", err)
	}
	if err := reissue("", pendingOwner); err != nil {
		t.Fatalf("platform console -> pending owner: %v", err)
	}
}
