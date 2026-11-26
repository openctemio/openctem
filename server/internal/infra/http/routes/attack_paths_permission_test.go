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

// The computed attack routes need attack_surface:paths:read: a caller who
// may list assets (assets:read, even assets:write) but lacks it is refused
// with the missing permission named, and one who holds it reaches the
// handler. The surface statistics stay on assets:read. The token's team role
// is viewer, whose defaults do not include the permission, so only the
// resolved permissions decide.
func TestAttackPathRoutes_NeedPathsRead(t *testing.T) {
	saved := []Middleware{csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware,
		permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware}
	t.Cleanup(func() {
		csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware = saved[0], saved[1], saved[2]
		permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware = saved[3], saved[4], saved[5]
	})
	csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware = nil, nil, nil
	permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware = nil, nil, nil

	gen := jwt.NewGenerator(jwt.TokenConfig{Secret: "attack-paths-route-test-secret-0123456789", Issuer: "test",
		AccessTokenDuration: time.Hour, RefreshTokenDuration: time.Hour})
	auth := middleware.UnifiedAuth(middleware.UnifiedAuthConfig{Provider: config.AuthProviderLocal, LocalValidator: gen})
	setPerms := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			perms := strings.Split(r.Header.Get("X-Test-Perms"), ",")
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), middleware.PermissionsKey, perms)))
		})
	}
	pass := func(next http.Handler) http.Handler { return next }
	router := infrahttp.NewChiRouter()
	registerAttackSurfaceRoutes(router, &handler.AttackSurfaceHandler{}, auth, setPerms, pass)
	registerThreatModelRoutes(router, &handler.ThreatModelHandler{}, auth, setPerms, pass)
	mux := router.(interface{ Handler() http.Handler }).Handler()

	tok, err := gen.GenerateTenantScopedAccessToken(shared.NewID().String(), "m@acme.test", "M", shared.NewID().String(),
		jwt.TenantMembership{TenantID: shared.NewID().String(), TenantSlug: "acme", Role: "viewer"}, false, 0, "password")
	if err != nil {
		t.Fatal(err)
	}
	type refusal struct {
		Code    string `json:"code"`
		Details struct {
			Missing []string `json:"missing_permissions"`
		} `json:"details"`
	}
	call := func(perms, method, path string) (code int, ref refusal) {
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
		_ = json.Unmarshal(rec.Body.Bytes(), &ref)
		return rec.Code, ref
	}

	inventory := permission.AssetsRead.String() + "," + permission.AssetsWrite.String()
	withPaths := inventory + "," + permission.AttackPathsRead.String()
	id := shared.NewID().String()
	gated := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/attack-surface/attack-paths"},
		{http.MethodGet, "/api/v1/attack-surface/attack-paths/" + id},
		{http.MethodGet, "/api/v1/attack-surface/exposure-chains"},
		{http.MethodGet, "/api/v1/threat-models/"},
		{http.MethodGet, "/api/v1/threat-models/" + id},
		{http.MethodGet, "/api/v1/threat-models/" + id + "/coverage"},
		{http.MethodPost, "/api/v1/threat-models/generate"},
	}
	for _, g := range gated {
		name := g.method + " " + g.path
		code, ref := call(inventory, g.method, g.path)
		if code != http.StatusForbidden || len(ref.Details.Missing) != 1 || ref.Details.Missing[0] != permission.AttackPathsRead.String() {
			t.Errorf("%s with inventory only: %d %+v, want 403 naming %s", name, code, ref, permission.AttackPathsRead)
		}
		if code, ref := call(withPaths, g.method, g.path); code == http.StatusForbidden || code == http.StatusUnauthorized {
			t.Errorf("%s with the permission: refused %d %+v", name, code, ref)
		}
	}
	// Generating still needs assets:write as well.
	if code, _ := call(permission.AssetsRead.String()+","+permission.AttackPathsRead.String(), http.MethodPost, "/api/v1/threat-models/generate"); code != http.StatusForbidden {
		t.Errorf("generate without assets:write: %d, want 403", code)
	}
	// The surface statistics are inventory.
	if code, _ := call(permission.AssetsRead.String(), http.MethodGet, "/api/v1/attack-surface/stats"); code == http.StatusForbidden {
		t.Error("stats refused with assets:read")
	}
}
