package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	modulesvc "github.com/openctemio/openctem/api/internal/app/module"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type etagModuleRepo struct{}

func (etagModuleRepo) ListAllModules(context.Context) ([]*moduledom.Module, error) { return nil, nil }
func (etagModuleRepo) ListActiveModules(context.Context) ([]*moduledom.Module, error) {
	return nil, nil
}
func (etagModuleRepo) GetModuleByID(context.Context, string) (*moduledom.Module, error) {
	return nil, nil
}
func (etagModuleRepo) GetSubModules(context.Context, string) ([]*moduledom.Module, error) {
	return nil, nil
}
func (etagModuleRepo) ListAllSubModules(context.Context) (map[string][]*moduledom.Module, error) {
	return nil, nil
}

func modulesHandler() *BootstrapHandler {
	return NewBootstrapHandler(nil, nil, modulesvc.NewModuleService(etagModuleRepo{}, logger.NewNop()), nil, logger.NewNop()).
		WithModulesETagKey([]byte("test-key-0123456789abcdef0123456"))
}

func modulesRequest(tenantID, userID string, admin bool, ifNoneMatch string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/me/modules", nil)
	ctx := context.WithValue(r.Context(), middleware.TenantIDKey, tenantID)
	ctx = context.WithValue(ctx, middleware.UserIDKey, userID)
	ctx = context.WithValue(ctx, middleware.IsAdminKey, admin)
	if ifNoneMatch != "" {
		r.Header.Set("If-None-Match", ifNoneMatch)
	}
	w := httptest.NewRecorder()
	modulesHandler().GetTenantModules(w, r.WithContext(ctx))
	return w
}

// The modules payload depends on the caller's permissions. On a shared
// browser profile user B's request carries user A's cached ETag; with an
// ETag made only of the tenant and two small counters, B got a 304 and the
// browser showed A's payload. The ETag is now bound to the user.
func TestGetTenantModules_ETagIsBoundToTheUser(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	const userA, userB = "22222222-2222-2222-2222-222222222222", "33333333-3333-3333-3333-333333333333"

	a := modulesRequest(tenant, userA, false, "")
	etagA := a.Header().Get("ETag")
	if a.Code != http.StatusOK || etagA == "" {
		t.Fatalf("A: %d etag %q", a.Code, etagA)
	}
	// Same user, same state: still revalidates.
	if again := modulesRequest(tenant, userA, false, etagA); again.Code != http.StatusNotModified {
		t.Fatalf("A revalidating its own ETag = %d, want 304", again.Code)
	}
	// Another user of the same tenant with the same counters: full answer.
	if b := modulesRequest(tenant, userB, false, etagA); b.Code != http.StatusOK || b.Header().Get("ETag") == etagA {
		t.Fatalf("B with A's ETag = %d (etag %q), want 200 with its own ETag", b.Code, b.Header().Get("ETag"))
	}
	// The same user as admin sees a different payload.
	if adm := modulesRequest(tenant, userA, true, etagA); adm.Code != http.StatusOK {
		t.Fatalf("A as admin with A's member ETag = %d, want 200", adm.Code)
	}
	// Tenants that share the first 8 characters of their id.
	if other := modulesRequest("11111111-9999-9999-9999-999999999999", userA, false, etagA); other.Code != http.StatusOK {
		t.Fatalf("other tenant with the same id prefix = %d, want 200", other.Code)
	}
	if cc := a.Header().Get("Cache-Control"); !strings.Contains(cc, "private") {
		t.Fatalf("Cache-Control = %q, want private", cc)
	}
	if v := a.Header().Get("Vary"); !strings.Contains(v, "Authorization") || !strings.Contains(v, "Cookie") {
		t.Fatalf("Vary = %q, want Authorization and Cookie", v)
	}
	if strings.Contains(etagA, tenant[:8]) {
		t.Fatalf("ETag %q reveals the tenant id", etagA)
	}
}

func TestDeriveModulesETagKey(t *testing.T) {
	k1, k2 := DeriveModulesETagKey("secret-a"), DeriveModulesETagKey("secret-a")
	if len(k1) != 32 || string(k1) != string(k2) || string(k1) == "secret-a" {
		t.Fatalf("key = %x / %x", k1, k2)
	}
	if string(DeriveModulesETagKey("secret-b")) == string(k1) {
		t.Fatal("different secrets, same key")
	}
	if DeriveModulesETagKey("") != nil {
		t.Fatal("empty secret must give no key")
	}
}
