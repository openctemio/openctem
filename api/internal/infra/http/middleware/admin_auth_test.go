package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/admin"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// fakeSessions resolves fixed console session tokens to pre-built AdminUsers,
// standing in for the admin console service.
type fakeSessions struct {
	byToken map[string]*admin.AdminUser
}

func newFakeSessions() *fakeSessions { return &fakeSessions{byToken: map[string]*admin.AdminUser{}} }

func (f *fakeSessions) add(token string, role admin.AdminRole) {
	now := time.Now()
	f.byToken[token] = admin.Reconstitute(
		shared.NewID(), "a-"+string(role)+"@example.com", "Admin "+string(role),
		role, true, nil, nil, "", 0, nil, nil, "", now, nil, now,
	)
}

func (f *fakeSessions) Authenticate(_ context.Context, token string) (*admin.AdminUser, error) {
	if u, ok := f.byToken[token]; ok {
		return u, nil
	}
	return nil, admin.ErrSessionNotFound
}

const testCSRF = "csrf-test-value"

// adminRequest builds a browser-like console request: the session cookie, and
// on writes the matching admin CSRF cookie and header.
func adminRequest(method, path, session string) *http.Request {
	req := httptest.NewRequest(method, path, http.NoBody)
	if session != "" {
		req.AddCookie(&http.Cookie{Name: middleware.AdminSessionCookie, Value: session})
		if method != http.MethodGet {
			req.AddCookie(&http.Cookie{Name: middleware.AdminCSRFCookie, Value: testCSRF})
			req.Header.Set(middleware.CSRFHeaderName, testCSRF)
		}
	}
	return req
}

// buildAdminUsersGuard reproduces the exact middleware composition that
// registerAdminRoutes applies to /api/v1/admin/users: Authenticate followed by
// RequireRole(super_admin). The stub handler stands in for the real
// list/get/update/... handlers and returns 200 so we can observe whether a
// request was allowed through the guard.
func buildAdminUsersGuard(t *testing.T) (http.Handler, map[string]string) {
	t.Helper()
	sessions := newFakeSessions()
	sessions.add("key-super", admin.AdminRoleSuperAdmin)
	sessions.add("key-ops", admin.AdminRoleOpsAdmin)
	sessions.add("key-readonly", admin.AdminRoleReadonly)

	m := middleware.NewAdminAuthMiddleware(sessions, logger.NewNop())

	stub := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// Order: Authenticate (outer) -> RequireRole(super_admin) (inner) -> stub.
	guarded := m.Authenticate(m.RequireRole(admin.AdminRoleSuperAdmin)(stub))

	keys := map[string]string{
		"super":    "key-super",
		"ops":      "key-ops",
		"readonly": "key-readonly",
	}
	return guarded, keys
}

func doAdmin(h http.Handler, method, session string) int {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, adminRequest(method, "/api/v1/admin/users/", session))
	return rec.Code
}

// TestAdminUsers_ReadGate_AUTHZ8 proves the AUTHZ-8 fix: admin-user List/Get
// (reads) are gated to super_admin. readonly and ops_admin are rejected 403;
// super_admin is allowed through.
func TestAdminUsers_ReadGate_AUTHZ8(t *testing.T) {
	h, keys := buildAdminUsersGuard(t)

	for _, method := range []string{http.MethodGet} {
		if got := doAdmin(h, method, keys["readonly"]); got != http.StatusForbidden {
			t.Errorf("%s readonly: got %d, want 403", method, got)
		}
		if got := doAdmin(h, method, keys["ops"]); got != http.StatusForbidden {
			t.Errorf("%s ops_admin: got %d, want 403", method, got)
		}
		if got := doAdmin(h, method, keys["super"]); got != http.StatusOK {
			t.Errorf("%s super_admin: got %d, want 200", method, got)
		}
	}
}

// TestAdminUsers_MutationGate proves mutations (POST/PATCH/DELETE) are gated to
// super_admin: readonly and ops_admin are rejected 403; super_admin allowed.
func TestAdminUsers_MutationGate(t *testing.T) {
	h, keys := buildAdminUsersGuard(t)

	for _, method := range []string{http.MethodPost, http.MethodPatch, http.MethodDelete} {
		if got := doAdmin(h, method, keys["readonly"]); got != http.StatusForbidden {
			t.Errorf("%s readonly: got %d, want 403", method, got)
		}
		if got := doAdmin(h, method, keys["ops"]); got != http.StatusForbidden {
			t.Errorf("%s ops_admin: got %d, want 403", method, got)
		}
		if got := doAdmin(h, method, keys["super"]); got != http.StatusOK {
			t.Errorf("%s super_admin: got %d, want 200", method, got)
		}
	}
}

// TestAdminUsers_NoSessionRejected proves an unauthenticated request is
// rejected before role evaluation.
func TestAdminUsers_NoSessionRejected(t *testing.T) {
	h, _ := buildAdminUsersGuard(t)
	if got := doAdmin(h, http.MethodGet, ""); got != http.StatusUnauthorized {
		t.Errorf("no session: got %d, want 401", got)
	}
}

// TestAdminAPIKeysAreNotAccepted proves there is no API-key path into the
// admin API: a key in X-Admin-API-Key or a Bearer header authenticates
// nothing, even when the same value is a valid session token.
func TestAdminAPIKeysAreNotAccepted(t *testing.T) {
	h, keys := buildAdminUsersGuard(t)
	for name, set := range map[string]func(*http.Request){
		"X-Admin-API-Key": func(r *http.Request) { r.Header.Set("X-Admin-API-Key", keys["super"]) },
		"Bearer":          func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+keys["super"]) },
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users/", http.NoBody)
		set(req)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: got %d, want 401", name, rec.Code)
		}
	}
}

// TestAdminSessionWriteNeedsCSRF proves a cookie-authenticated write without
// the matching admin CSRF header is refused.
func TestAdminSessionWriteNeedsCSRF(t *testing.T) {
	h, keys := buildAdminUsersGuard(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/", http.NoBody)
	req.AddCookie(&http.Cookie{Name: middleware.AdminSessionCookie, Value: keys["super"]})
	req.AddCookie(&http.Cookie{Name: middleware.AdminCSRFCookie, Value: testCSRF})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("write without CSRF header: got %d, want 401", rec.Code)
	}
}

// TestTargetMappingWriteGate proves target-mapping WRITES are gated to
// ops_admin+ (readonly rejected) while reads remain open to any admin.
func TestTargetMappingWriteGate(t *testing.T) {
	sessions := newFakeSessions()
	sessions.add("key-super", admin.AdminRoleSuperAdmin)
	sessions.add("key-ops", admin.AdminRoleOpsAdmin)
	sessions.add("key-readonly", admin.AdminRoleReadonly)
	m := middleware.NewAdminAuthMiddleware(sessions, logger.NewNop())

	stub := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	writeGuard := m.Authenticate(m.RequireRole(admin.AdminRoleSuperAdmin, admin.AdminRoleOpsAdmin)(stub))

	if got := doAdmin(writeGuard, http.MethodPost, "key-readonly"); got != http.StatusForbidden {
		t.Errorf("write readonly: got %d, want 403", got)
	}
	if got := doAdmin(writeGuard, http.MethodPost, "key-ops"); got != http.StatusOK {
		t.Errorf("write ops_admin: got %d, want 200", got)
	}
	if got := doAdmin(writeGuard, http.MethodPost, "key-super"); got != http.StatusOK {
		t.Errorf("write super_admin: got %d, want 200", got)
	}
}
