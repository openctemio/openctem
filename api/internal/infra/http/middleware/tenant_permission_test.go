package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
)

type fakeTenantChecker struct {
	allowed map[string]bool // tenantID|userID|perm
	err     error
	calls   int
}

func (f *fakeTenantChecker) HasPermission(_ context.Context, tenantID, userID, perm string) (bool, error) {
	f.calls++
	if f.err != nil {
		return false, f.err
	}
	return f.allowed[tenantID+"|"+userID+"|"+perm], nil
}

func tenantPermRequest(t *testing.T, tenantID shared.ID, role tenant.Role, withUser bool) (*http.Request, *userdom.User) {
	t.Helper()
	ctx := context.Background()
	if !tenantID.IsZero() {
		ctx = context.WithValue(ctx, TeamIDKey, tenantID)
	}
	if role != "" {
		ctx = context.WithValue(ctx, TeamRoleKey, role)
	}
	var u *userdom.User
	if withUser {
		var err error
		u, err = userdom.NewProvisionedLocalUser("u@acme.test", "U")
		if err != nil {
			t.Fatal(err)
		}
		ctx = context.WithValue(ctx, LocalUserKey, u)
	}
	return httptest.NewRequest(http.MethodGet, "/api/v1/tenants/acme/members", nil).WithContext(ctx), u
}

func runTenantPerm(checker TenantPermissionChecker, r *http.Request) int {
	rec := httptest.NewRecorder()
	RequireTenantPermission(checker, "team:members:read")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, r)
	return rec.Code
}

func TestRequireTenantPermission(t *testing.T) {
	tid := shared.NewID()

	t.Run("holder in the path tenant passes", func(t *testing.T) {
		r, u := tenantPermRequest(t, tid, tenant.RoleViewer, true)
		c := &fakeTenantChecker{allowed: map[string]bool{tid.String() + "|" + u.ID().String() + "|team:members:read": true}}
		if code := runTenantPerm(c, r); code != http.StatusOK {
			t.Fatalf("got %d", code)
		}
	})
	t.Run("permission held in another tenant does not count", func(t *testing.T) {
		r, u := tenantPermRequest(t, tid, tenant.RoleViewer, true)
		c := &fakeTenantChecker{allowed: map[string]bool{shared.NewID().String() + "|" + u.ID().String() + "|team:members:read": true}}
		if code := runTenantPerm(c, r); code != http.StatusForbidden {
			t.Fatalf("got %d, want 403", code)
		}
	})
	t.Run("admin membership without the permission is refused", func(t *testing.T) {
		r, _ := tenantPermRequest(t, tid, tenant.RoleAdmin, true)
		if code := runTenantPerm(&fakeTenantChecker{}, r); code != http.StatusForbidden {
			t.Fatalf("got %d, want 403", code)
		}
	})
	t.Run("owner passes without a lookup", func(t *testing.T) {
		r, _ := tenantPermRequest(t, tid, tenant.RoleOwner, true)
		c := &fakeTenantChecker{}
		if code := runTenantPerm(c, r); code != http.StatusOK || c.calls != 0 {
			t.Fatalf("got %d with %d lookups", code, c.calls)
		}
	})
	t.Run("lookup error refuses", func(t *testing.T) {
		r, _ := tenantPermRequest(t, tid, tenant.RoleMember, true)
		if code := runTenantPerm(&fakeTenantChecker{err: errors.New("redis down")}, r); code != http.StatusInternalServerError {
			t.Fatalf("got %d, want 500", code)
		}
	})
	t.Run("no membership in context refuses", func(t *testing.T) {
		r, _ := tenantPermRequest(t, shared.ID{}, "", true)
		if code := runTenantPerm(&fakeTenantChecker{}, r); code != http.StatusForbidden {
			t.Fatalf("got %d, want 403", code)
		}
	})
	t.Run("no local user refuses", func(t *testing.T) {
		r, _ := tenantPermRequest(t, tid, tenant.RoleMember, false)
		if code := runTenantPerm(&fakeTenantChecker{}, r); code != http.StatusForbidden {
			t.Fatalf("got %d, want 403", code)
		}
	})
}
