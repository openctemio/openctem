package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type disabledModules map[string]map[string]bool // tenant -> module -> off

func (d disabledModules) TenantDisabledModules(_ context.Context, tenantID string) map[string]bool {
	return d[tenantID]
}

// The AI triage routes follow the ai_triage module: off answers
// MODULE_NOT_ENABLED for that organization only.
func TestAITriageRoutes_FollowTheModule(t *testing.T) {
	const off, on = "018f5a1e-0000-7000-8000-00000000000a", "018f5a1e-0000-7000-8000-00000000000b"
	gate := middleware.NewModuleGate(disabledModules{off: {"ai_triage": true}}, 0)

	serve := func(tenant, method, path string) (int, string) {
		router := infrahttp.NewChiRouter()
		as := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c := context.WithValue(r.Context(), middleware.IsAdminKey, true)
				c = context.WithValue(c, middleware.TenantIDKey, tenant)
				next.ServeHTTP(w, r.WithContext(c))
			})
		}
		registerAITriageRoutes(router, handler.NewAITriageHandler(nil, logger.NewNop()), as, nil, nil,
			gate.RequireModule("ai_triage"))
		rec := httptest.NewRecorder()
		router.(interface{ Handler() http.Handler }).Handler().ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec.Code, rec.Body.String()
	}

	const finding = "/api/v1/findings/018f5a1e-0000-7000-8000-0000000000cc/ai-triage"
	routes := []struct{ method, path string }{
		{http.MethodPost, finding},
		{http.MethodGet, finding + "/"},
		{http.MethodGet, finding + "/history"},
		{http.MethodGet, "/api/v1/findings/ai-triage/config"},
		{http.MethodPost, "/api/v1/findings/ai-triage/bulk"},
	}
	for _, rt := range routes {
		code, body := serve(off, rt.method, rt.path)
		if code != http.StatusForbidden || !strings.Contains(body, "MODULE_NOT_ENABLED") {
			t.Errorf("module off: %s %s = %d %s, want 403 MODULE_NOT_ENABLED", rt.method, rt.path, code, body)
		}
		if code, body := serve(on, rt.method, rt.path); strings.Contains(body, "MODULE_NOT_ENABLED") {
			t.Errorf("module on: %s %s = %d %s, want it past the module gate", rt.method, rt.path, code, body)
		}
	}
}
