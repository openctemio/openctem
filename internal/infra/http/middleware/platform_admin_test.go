package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/api/pkg/keycloak"
)

// TestIsPlatformAdmin covers the three ways a principal can be recognized as an
// application (platform) administrator, and the default-deny case. This is the
// gate that fronts tenant SSO/SAML setup, so the deny path matters most.
func TestIsPlatformAdmin(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		want bool
	}{
		{
			name: "empty context is not platform admin",
			ctx:  context.Background(),
			want: false,
		},
		{
			name: "tenant admin (IsAdmin) is NOT platform admin",
			ctx:  context.WithValue(context.Background(), IsAdminKey, true),
			want: false,
		},
		{
			name: "allow-list flag stamped by UnifiedAuth grants platform admin",
			ctx:  context.WithValue(context.Background(), IsPlatformAdminKey, true),
			want: true,
		},
		{
			name: "allow-list flag explicitly false denies",
			ctx:  context.WithValue(context.Background(), IsPlatformAdminKey, false),
			want: false,
		},
		{
			name: "keycloak platform_admin realm role grants platform admin",
			ctx: context.WithValue(context.Background(), ClaimsKey, &keycloak.Claims{
				RealmAccess: keycloak.RealmAccess{Roles: []string{"member", RolePlatformAdmin}},
			}),
			want: true,
		},
		{
			name: "keycloak system_admin realm role grants platform admin",
			ctx: context.WithValue(context.Background(), ClaimsKey, &keycloak.Claims{
				RealmAccess: keycloak.RealmAccess{Roles: []string{RoleSystemAdmin}},
			}),
			want: true,
		},
		{
			name: "keycloak realm role without platform role denies",
			ctx: context.WithValue(context.Background(), ClaimsKey, &keycloak.Claims{
				RealmAccess: keycloak.RealmAccess{Roles: []string{"owner", "admin"}},
			}),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPlatformAdmin(tt.ctx); got != tt.want {
				t.Fatalf("IsPlatformAdmin() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestRequirePlatformAdmin verifies the middleware 403s a tenant admin and lets
// a stamped platform admin through — the exact behavior that keeps tenant
// owners/admins from self-serving SSO setup.
func TestRequirePlatformAdmin(t *testing.T) {
	handlerReached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerReached = true
		w.WriteHeader(http.StatusOK)
	})
	mw := RequirePlatformAdmin()(next)

	t.Run("tenant admin is forbidden", func(t *testing.T) {
		handlerReached = false
		req := httptest.NewRequest(http.MethodGet, "/api/v1/settings/saml", nil).
			WithContext(context.WithValue(context.Background(), IsAdminKey, true))
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
		}
		if handlerReached {
			t.Fatal("handler must not run for a non-platform-admin")
		}
	})

	t.Run("platform admin is allowed", func(t *testing.T) {
		handlerReached = false
		req := httptest.NewRequest(http.MethodGet, "/api/v1/settings/saml", nil).
			WithContext(context.WithValue(context.Background(), IsPlatformAdminKey, true))
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}
		if !handlerReached {
			t.Fatal("handler must run for a platform admin")
		}
	})
}
