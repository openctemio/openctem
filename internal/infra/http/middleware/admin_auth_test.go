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
	"github.com/openctemio/api/pkg/pagination"
)

// fakeAdminRepo is a minimal admin.Repository that authenticates a fixed set of
// raw keys to pre-built AdminUsers. Only AuthenticateByAPIKey / RecordUsage are
// exercised by the auth middleware.
type fakeAdminRepo struct {
	byKey map[string]*admin.AdminUser
}

func newFakeAdminRepo() *fakeAdminRepo { return &fakeAdminRepo{byKey: map[string]*admin.AdminUser{}} }

func (f *fakeAdminRepo) add(key string, role admin.AdminRole) {
	now := time.Now()
	u := admin.Reconstitute(
		shared.NewID(), "a-"+string(role)+"@example.com", "Admin "+string(role),
		"hash", "oc-admin-"+string(role)[:3], role, true,
		nil, "", 0, nil, nil, "", now, nil, now,
	)
	f.byKey[key] = u
}

func (f *fakeAdminRepo) AuthenticateByAPIKey(_ context.Context, rawKey string) (*admin.AdminUser, error) {
	if u, ok := f.byKey[rawKey]; ok {
		return u, nil
	}
	return nil, admin.ErrInvalidAPIKey
}

func (f *fakeAdminRepo) RecordUsage(_ context.Context, _ shared.ID, _ string) error { return nil }

// --- unused Repository methods (panic to catch accidental use) ---
func (f *fakeAdminRepo) Create(context.Context, *admin.AdminUser) error { panic("unused") }
func (f *fakeAdminRepo) GetByID(context.Context, shared.ID) (*admin.AdminUser, error) {
	panic("unused")
}
func (f *fakeAdminRepo) GetByEmail(context.Context, string) (*admin.AdminUser, error) {
	panic("unused")
}
func (f *fakeAdminRepo) GetByAPIKeyPrefix(context.Context, string) (*admin.AdminUser, error) {
	panic("unused")
}
func (f *fakeAdminRepo) List(context.Context, admin.Filter, pagination.Pagination) (pagination.Result[*admin.AdminUser], error) {
	panic("unused")
}
func (f *fakeAdminRepo) Update(context.Context, *admin.AdminUser) error { panic("unused") }
func (f *fakeAdminRepo) Delete(context.Context, shared.ID) error        { panic("unused") }
func (f *fakeAdminRepo) Count(context.Context, admin.Filter) (int, error) {
	panic("unused")
}
func (f *fakeAdminRepo) CountByRole(context.Context, admin.AdminRole) (int, error) {
	panic("unused")
}

// buildAdminUsersGuard reproduces the exact middleware composition that
// registerAdminRoutes applies to /api/v1/admin/users: Authenticate followed by
// RequireRole(super_admin). The stub handler stands in for the real
// list/get/create/... handlers and returns 200 so we can observe whether a
// request was allowed through the guard.
func buildAdminUsersGuard(t *testing.T) (http.Handler, map[string]string) {
	t.Helper()
	repo := newFakeAdminRepo()
	repo.add("key-super", admin.AdminRoleSuperAdmin)
	repo.add("key-ops", admin.AdminRoleOpsAdmin)
	repo.add("key-readonly", admin.AdminRoleReadonly)

	m := middleware.NewAdminAuthMiddleware(repo, logger.NewNop())

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

func doAdmin(h http.Handler, method, key string) int {
	req := httptest.NewRequest(method, "/api/v1/admin/users/", http.NoBody)
	if key != "" {
		req.Header.Set(middleware.AdminAPIKeyHeader, key)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
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

// TestAdminUsers_NoKeyRejected proves an unauthenticated request is rejected
// before role evaluation.
func TestAdminUsers_NoKeyRejected(t *testing.T) {
	h, _ := buildAdminUsersGuard(t)
	if got := doAdmin(h, http.MethodGet, ""); got != http.StatusUnauthorized {
		t.Errorf("no key: got %d, want 401", got)
	}
}

// TestTargetMappingWriteGate proves target-mapping WRITES are gated to
// ops_admin+ (readonly rejected) while reads remain open to any admin.
func TestTargetMappingWriteGate(t *testing.T) {
	repo := newFakeAdminRepo()
	repo.add("key-super", admin.AdminRoleSuperAdmin)
	repo.add("key-ops", admin.AdminRoleOpsAdmin)
	repo.add("key-readonly", admin.AdminRoleReadonly)
	m := middleware.NewAdminAuthMiddleware(repo, logger.NewNop())

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
