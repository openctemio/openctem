package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// Generating a threat model reads the tenant's whole exposure graph, so it
// shares the per-tenant cap of the other heavy reads: while the tenant's
// slots are all taken, a generate request waits and, when its context ends,
// is refused with 503 BUSY instead of reaching the handler. Another tenant
// is not held back.
func TestThreatModelGenerate_SharesHeavyReadCap(t *testing.T) {
	saved := []Middleware{csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware,
		permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware}
	t.Cleanup(func() {
		csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware = saved[0], saved[1], saved[2]
		permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware = saved[3], saved[4], saved[5]
	})
	csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware = nil, nil, nil
	permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware = nil, nil, nil

	gen := jwt.NewGenerator(jwt.TokenConfig{Secret: "threat-model-heavy-read-test-secret-0123", Issuer: "test",
		AccessTokenDuration: time.Hour, RefreshTokenDuration: time.Hour})
	auth := middleware.UnifiedAuth(middleware.UnifiedAuthConfig{Provider: config.AuthProviderLocal, LocalValidator: gen})
	perms := []string{permission.AssetsWrite.String(), permission.AttackPathsRead.String()}
	setPerms := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), middleware.PermissionsKey, perms)))
		})
	}
	pass := func(next http.Handler) http.Handler { return next }
	router := infrahttp.NewChiRouter()
	registerThreatModelRoutes(router, &handler.ThreatModelHandler{}, auth, setPerms, pass)
	mux := router.(interface{ Handler() http.Handler }).Handler()

	busyTenant, freeTenant := shared.NewID().String(), shared.NewID().String()
	token := func(tenantID string) string {
		tok, err := gen.GenerateTenantScopedAccessToken(shared.NewID().String(), "m@example.com", "M", shared.NewID().String(),
			jwt.TenantMembership{TenantID: tenantID, TenantSlug: "example", Role: "admin"}, false, 0, "password")
		if err != nil {
			t.Fatal(err)
		}
		return tok.AccessToken
	}

	// Take every heavy-read slot of busyTenant.
	release := make(chan struct{})
	var holders, started sync.WaitGroup
	hold := heavyReads.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		started.Done()
		<-release
	}))
	const slots = 4
	started.Add(slots)
	for range slots {
		holders.Add(1)
		go func() {
			defer holders.Done()
			ctx := context.WithValue(context.Background(), middleware.TenantIDKey, busyTenant)
			hold.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(ctx, http.MethodGet, "/", nil))
		}()
	}
	started.Wait()
	t.Cleanup(func() { close(release); holders.Wait() })

	generate := func(tenantID string) (code int, reached bool, body string) {
		defer func() {
			if recover() != nil {
				reached = true // the zero handler panics on its nil service
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/threat-models/generate",
			strings.NewReader(`{"scope_type":"tenant"}`))
		req.Header.Set("Authorization", "Bearer "+token(tenantID))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code, false, rec.Body.String()
	}

	code, reached, body := generate(busyTenant)
	if reached || code != http.StatusServiceUnavailable || !strings.Contains(body, "BUSY") {
		t.Fatalf("generate while the tenant's heavy reads are full: code=%d reached=%v body=%.200s, want 503 BUSY before the handler", code, reached, body)
	}
	if _, reached, _ := generate(freeTenant); !reached {
		t.Fatal("generate for another tenant did not reach the handler: the cap must be per tenant")
	}
}
