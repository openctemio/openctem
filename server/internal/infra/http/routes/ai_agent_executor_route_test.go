package routes

// PUT /api/v1/ai/agents/{id}/executor decides where an AI agent's finding
// data goes: service_accounts:manage and a recent sign-in, and only the
// executors that exist (built in, the organization's AI workers).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/app/aianalysis"
	"github.com/openctemio/openctem/server/internal/config"
	infrahttp "github.com/openctemio/openctem/server/internal/infra/http"
	"github.com/openctemio/openctem/server/internal/infra/http/handler"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/jwt"
	"github.com/openctemio/openctem/server/pkg/logger"
)

func TestAIAgentExecutorRoute_ManageStepUpAndKnownExecutors(t *testing.T) {
	saved := []Middleware{csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware,
		permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware}
	t.Cleanup(func() {
		csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware = saved[0], saved[1], saved[2]
		permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware = saved[3], saved[4], saved[5]
	})
	csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware = nil, nil, nil
	permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware = nil, nil, nil

	gen := jwt.NewGenerator(jwt.TokenConfig{Secret: "ai-executor-route-test-secret-0123456789", Issuer: "test",
		AccessTokenDuration: time.Hour, RefreshTokenDuration: time.Hour})
	tenantID := shared.NewID().String()
	token := func(role string, admin bool) string {
		tok, err := gen.GenerateTenantScopedAccessToken(shared.NewID().String(), role+"@example.com", role, shared.NewID().String(),
			jwt.TenantMembership{TenantID: tenantID, TenantSlug: "acme", Role: role}, admin, 0, "password")
		if err != nil {
			t.Fatal(err)
		}
		return tok.AccessToken
	}
	owner, member := token("owner", true), token("member", false)
	auth := middleware.UnifiedAuth(middleware.UnifiedAuthConfig{Provider: config.AuthProviderLocal, LocalValidator: gen})
	pass := func(next http.Handler) http.Handler { return next }

	// The service refuses an unknown executor before it reads anything, so a
	// service without repositories is enough here.
	svc := aianalysis.New(nil, nil, nil, nil, nil, nil, logger.NewNop())
	var mux http.Handler
	// Registration captures the step-up checker: mount after setting it.
	mount := func(c middleware.RecentAuthChecker) {
		withStepUpChecker(t, c)
		router := infrahttp.NewChiRouter()
		registerAIAnalysisRoutes(router, handler.NewAIAnalysisHandler(svc, logger.NewNop()), auth, nil, pass, nil)
		mux = router.(interface{ Handler() http.Handler }).Handler()
	}

	call := func(tok, executor string) (int, string) {
		body := strings.NewReader(`{"executor":"` + executor + `"}`)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/api/v1/ai/agents/"+shared.NewID().String()+"/executor", body)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var e struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &e)
		return rec.Code, e.Code
	}

	mount(steppedUpAt(time.Now()))
	if code, _ := call(member, "tenant_worker"); code != http.StatusForbidden {
		t.Fatalf("a member without service_accounts:manage: %d, want 403", code)
	}
	for _, ex := range []string{"platform_worker", "external"} {
		if code, _ := call(owner, ex); code != http.StatusBadRequest {
			t.Fatalf("executor %s: %d, want 400", ex, code)
		}
	}
	mount(steppedUpAt(time.Now().Add(-time.Hour)))
	if code, problem := call(owner, "tenant_worker"); code != http.StatusForbidden || problem != string(middleware.CodeStepUpRequired) {
		t.Fatalf("without a recent sign-in: %d %s, want 403 %s", code, problem, middleware.CodeStepUpRequired)
	}
}
