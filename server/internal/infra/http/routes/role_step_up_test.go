package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/config"
	infrahttp "github.com/openctemio/openctem/server/internal/infra/http"
	"github.com/openctemio/openctem/server/internal/infra/http/handler"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/domain/permission"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/jwt"
)

// Role writes for a member (not an administrator): without the role
// permission the permission gate refuses first (no step-up prompt that would
// tell them the action exists for them); with it, a session outside the
// step-up window is asked to re-authenticate. Reads never ask for step-up.
func TestRoleRoutes_MemberPermissionThenStepUp(t *testing.T) {
	saved := []Middleware{csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware,
		permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware}
	t.Cleanup(func() {
		csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware = saved[0], saved[1], saved[2]
		permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware = saved[3], saved[4], saved[5]
	})
	csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware = nil, nil, nil
	permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware = nil, nil, nil
	withStepUpChecker(t, steppedUpAt(time.Now().Add(-11*time.Minute)))

	gen := jwt.NewGenerator(jwt.TokenConfig{Secret: "role-step-up-route-test-secret-0123456789", Issuer: "test",
		AccessTokenDuration: time.Hour, RefreshTokenDuration: time.Hour})
	auth := middleware.UnifiedAuth(middleware.UnifiedAuthConfig{Provider: config.AuthProviderLocal, LocalValidator: gen})
	router := infrahttp.NewChiRouter()
	// The permission-sync step resolves a member's permissions; here the
	// test names them in a header.
	setPerms := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			perms := strings.Split(r.Header.Get("X-Test-Perms"), ",")
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), middleware.PermissionsKey, perms)))
		})
	}
	registerRoleRoutes(router, &handler.RoleHandler{}, auth, setPerms)
	mux := router.(interface{ Handler() http.Handler }).Handler()

	tok, err := gen.GenerateTenantScopedAccessToken(shared.NewID().String(), "m@acme.test", "M",
		shared.NewID().String(), jwt.TenantMembership{TenantID: shared.NewID().String(), TenantSlug: "acme", Role: "member"},
		false, 0, "password")
	if err != nil {
		t.Fatal(err)
	}
	call := func(perms, method, path string) (code int, errCode string) {
		defer func() {
			if recover() != nil {
				code = reachedHandler // a zero handler panics on its nil service
			}
		}()
		req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		req.Header.Set("X-Test-Perms", perms)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var e struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &e)
		return rec.Code, e.Code
	}

	reader := permission.RolesRead.String()
	manager := strings.Join([]string{permission.RolesRead.String(), permission.RolesWrite.String(),
		permission.RolesDelete.String(), permission.RolesAssign.String()}, ",")
	id := shared.NewID().String()
	writes := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/roles"},
		{http.MethodPut, "/api/v1/roles/" + id},
		{http.MethodDelete, "/api/v1/roles/" + id},
		{http.MethodPost, "/api/v1/roles/" + id + "/template/apply"},
		{http.MethodPost, "/api/v1/roles/" + id + "/members/bulk"},
		{http.MethodPost, "/api/v1/users/" + id + "/roles"},
		{http.MethodPut, "/api/v1/users/" + id + "/roles"},
	}
	for _, w := range writes {
		name := w.method + " " + w.path
		if code, ec := call(reader, w.method, w.path); code != http.StatusForbidden || strings.HasPrefix(ec, "STEP_UP") {
			t.Errorf("%s without the permission: %d %q, want 403 permission denied", name, code, ec)
		}
		if code, ec := call(manager, w.method, w.path); code != http.StatusForbidden || ec != string(middleware.CodeStepUpRequired) {
			t.Errorf("%s outside the window: %d %q, want 403 %s", name, code, ec, middleware.CodeStepUpRequired)
		}
	}
	// Reads and taking a role away need no step-up.
	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/roles"},
		{http.MethodGet, "/api/v1/roles/" + id + "/members"},
		{http.MethodDelete, "/api/v1/users/" + id + "/roles/" + id},
	} {
		if code, ec := call(manager, r.method, r.path); code == http.StatusForbidden && strings.HasPrefix(ec, "STEP_UP") {
			t.Errorf("%s %s asked for step-up", r.method, r.path)
		}
	}
}
