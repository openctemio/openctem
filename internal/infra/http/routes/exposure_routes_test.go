package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	infrahttp "github.com/openctemio/api/internal/infra/http"
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/permission"
	"github.com/openctemio/api/pkg/logger"
)

// A finding can become accepted or false_positive only through the approval
// workflow (request with findings:write, approve with findings:approve). The
// same dispositions on an exposure were open to any findings:write holder.
// They now need findings:approve; resolve and reactivate keep findings:write.
func TestExposureRoutes_DispositionsNeedApprover(t *testing.T) {
	const exposurePath = "/api/v1/exposures/01a0f6e2-35a7-7cae-af10-874c1481fe6e"

	serve := func(perms []string, method, path string) (code int, reachedHandler bool) {
		router := infrahttp.NewChiRouter()
		as := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := context.WithValue(r.Context(), middleware.IsAdminKey, false)
				ctx = context.WithValue(ctx, middleware.PermissionsKey, perms)
				ctx = context.WithValue(ctx, middleware.TenantIDKey, "01a0f6e2-35a7-7cae-af10-874c1481fe6f")
				next.ServeHTTP(w, r.WithContext(ctx))
			})
		}
		passthrough := func(next http.Handler) http.Handler { return next }
		// A nil service makes the handler panic once the gate lets the
		// request through, which is how "reached the handler" is observed.
		registerExposureRoutes(router, handler.NewExposureHandler(nil, nil, nil, logger.NewNop()), as, nil, passthrough)
		mux := router.(interface{ Handler() http.Handler }).Handler()
		defer func() {
			if recover() != nil {
				reachedHandler = true
			}
		}()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(`{"reason":"x"}`)))
		return rec.Code, false
	}

	member := []string{permission.FindingsRead.String(), permission.FindingsWrite.String()}
	approver := append([]string{permission.FindingsApprove.String()}, member...)

	for _, action := range []string{"/accept", "/false-positive"} {
		if code, reached := serve(member, http.MethodPost, exposurePath+action); reached || code != http.StatusForbidden {
			t.Errorf("findings:write only, POST %s: code=%d reached=%v, want 403", action, code, reached)
		}
		if _, reached := serve(approver, http.MethodPost, exposurePath+action); !reached {
			t.Errorf("findings:approve, POST %s: did not reach the handler", action)
		}
	}
	for _, action := range []string{"/resolve", "/reactivate"} {
		if _, reached := serve(member, http.MethodPost, exposurePath+action); !reached {
			t.Errorf("findings:write, POST %s: did not reach the handler", action)
		}
	}
}
