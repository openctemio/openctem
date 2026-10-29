package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformauthz"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type elevationSessions struct {
	a    *admin.AdminUser
	sess *admin.Session
}

func (s elevationSessions) Authenticate(context.Context, string) (*admin.AdminUser, error) {
	return s.a, nil
}
func (s elevationSessions) AuthenticateSession(context.Context, string) (*admin.AdminUser, *admin.Session, error) {
	// A fresh copy per request, as the real service loads it.
	cp := *s.a
	return &cp, s.sess, nil
}

// With elevation required, a super admin acts as read-only (super-admin
// routes refused) until the session holds a live elevation, and as read-only
// again once it has expired. The persisted role never changes.
func TestElevationGatesRoles(t *testing.T) {
	now := time.Now()
	a := admin.Reconstitute(shared.NewID(), "root@example.com", "Root", admin.AdminRoleSuperAdmin, true,
		nil, nil, "", 0, nil, nil, "", now, nil, now)
	sess := &admin.Session{ID: shared.NewID(), AdminID: a.ID(), MFAVerified: true, ExpiresAt: now.Add(time.Hour), LastSeenAt: now}
	call := func(m *AdminAuthMiddleware) (int, string) {
		var seen string
		h := m.Authenticate(m.RequirePlatform(platformauthz.AdminsRead)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = GetAdminRole(r.Context())
			w.WriteHeader(http.StatusNoContent)
		})))
		req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users/", nil)
		req.AddCookie(&http.Cookie{Name: AdminSessionCookie, Value: "s"})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, seen
	}
	m := NewAdminAuthMiddleware(elevationSessions{a: a, sess: sess}, logger.NewNop()).WithElevation(true)
	if code, _ := call(m); code != http.StatusForbidden {
		t.Fatalf("not elevated: %d, want 403", code)
	}
	until := now.Add(30 * time.Minute)
	sess.ElevatedRole, sess.ElevatedUntil = admin.AdminRoleSuperAdmin, &until
	if code, role := call(m); code != http.StatusNoContent || role != string(admin.AdminRoleSuperAdmin) {
		t.Fatalf("elevated: %d %s", code, role)
	}
	past := now.Add(-time.Minute)
	sess.ElevatedUntil = &past
	if code, _ := call(m); code != http.StatusForbidden {
		t.Fatalf("elevation expired: %d, want 403", code)
	}
	if a.Role() != admin.AdminRoleSuperAdmin {
		t.Fatal("the persisted role changed")
	}
	// Elevation off: the administrator's own role from sign-in.
	off := NewAdminAuthMiddleware(elevationSessions{a: a, sess: sess}, logger.NewNop())
	if code, _ := call(off); code != http.StatusNoContent {
		t.Fatalf("elevation off: %d", code)
	}
}

type fixedRoles struct {
	roles []platformauthz.RoleKey
	err   error
}

func (f fixedRoles) HeldRoles(context.Context, string) ([]platformauthz.RoleKey, error) {
	return f.roles, f.err
}

// Platform permissions (RFC-134): the guard works before or after the session
// check, a read-only administrator who holds the support role may use support
// permissions only while elevated as support, and a failure to read the roles
// refuses the request.
func TestRequirePlatform(t *testing.T) {
	now := time.Now()
	a := admin.Reconstitute(shared.NewID(), "s@example.com", "S", admin.AdminRoleReadonly, true,
		nil, nil, "", 0, nil, nil, "", now, nil, now)
	sess := &admin.Session{ID: shared.NewID(), AdminID: a.ID(), MFAVerified: true, ExpiresAt: now.Add(time.Hour), LastSeenAt: now}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	run := func(h http.Handler) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/platform-users/", nil)
		req.AddCookie(&http.Cookie{Name: AdminSessionCookie, Value: "s"})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	m := NewAdminAuthMiddleware(elevationSessions{a: a, sess: sess}, logger.NewNop()).WithElevation(true).
		WithPlatformRoles(fixedRoles{roles: []platformauthz.RoleKey{platformauthz.RoleViewer, platformauthz.RoleSupport}})
	after := m.Authenticate(m.RequirePlatform(platformauthz.UsersRead)(ok))
	before := m.RequirePlatform(platformauthz.UsersRead)(m.Authenticate(ok))
	baseline := m.Authenticate(m.RequirePlatform(platformauthz.TenantsRead)(ok))
	for name, h := range map[string]http.Handler{"guard after auth": after, "guard before auth": before} {
		if code := run(h); code != http.StatusForbidden {
			t.Fatalf("%s, not elevated: %d, want 403", name, code)
		}
	}
	if code := run(baseline); code != http.StatusNoContent {
		t.Fatalf("baseline read without elevation: %d", code)
	}
	until := now.Add(30 * time.Minute)
	sess.ElevatedRole, sess.ElevatedUntil = admin.AdminRole(platformauthz.RoleSupport), &until
	for name, h := range map[string]http.Handler{"guard after auth": after, "guard before auth": before} {
		if code := run(h); code != http.StatusNoContent {
			t.Fatalf("%s, elevated as support: %d", name, code)
		}
	}
	if code := run(m.Authenticate(m.RequirePlatform(platformauthz.AdminsManage)(ok))); code != http.StatusForbidden {
		t.Fatalf("support never manages administrators: %d", code)
	}
	// An elevation stored as a role the administrator no longer holds grants nothing.
	sess.ElevatedRole = admin.AdminRole(platformauthz.RoleOperator)
	if code := run(m.Authenticate(m.RequirePlatform(platformauthz.SensorsManage)(ok))); code != http.StatusForbidden {
		t.Fatalf("elevation to an unheld role: %d", code)
	}
	broken := NewAdminAuthMiddleware(elevationSessions{a: a, sess: sess}, logger.NewNop()).
		WithPlatformRoles(fixedRoles{err: context.DeadlineExceeded})
	if code := run(broken.Authenticate(ok)); code != http.StatusServiceUnavailable {
		t.Fatalf("roles unreadable: %d, want 503", code)
	}
	none := NewAdminAuthMiddleware(elevationSessions{a: a, sess: sess}, logger.NewNop()).WithPlatformRoles(fixedRoles{})
	if code := run(none.Authenticate(none.RequirePlatform(platformauthz.ConsoleRead)(ok))); code != http.StatusForbidden {
		t.Fatalf("no roles: %d, want 403", code)
	}
}
