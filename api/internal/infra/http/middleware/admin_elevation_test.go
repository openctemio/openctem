package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
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
		h := m.Authenticate(m.RequireRole(admin.AdminRoleSuperAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
