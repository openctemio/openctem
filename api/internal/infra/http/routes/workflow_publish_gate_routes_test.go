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
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The automation go-live routes need automations:publish (RFC-125 D7): a
// member who may edit drafts (automations:write) is refused publishing,
// approving, rolling back, changing the mode and deleting; a member who may
// only read is refused editing too.
func TestWorkflowRoutes_PublishNeedsPublishPermission(t *testing.T) {
	const tenant = "018f5a1e-0000-7000-8000-00000000001a"
	const wf = "/api/v1/workflows/018f5a1e-0000-7000-8000-0000000000aa"
	const ver = wf + "/versions/018f5a1e-0000-7000-8000-0000000000bb"
	serve := func(perms []string, method, path string) (int, string) {
		router := infrahttp.NewChiRouter()
		as := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c := context.WithValue(r.Context(), middleware.IsAdminKey, false)
				c = context.WithValue(c, middleware.TenantIDKey, tenant)
				c = context.WithValue(c, middleware.UserIDKey, "018f5a1e-0000-7000-8000-0000000000cc")
				c = context.WithValue(c, middleware.FetchedPermissionsKey, perms)
				next.ServeHTTP(w, r.WithContext(c))
			})
		}
		noop := func(next http.Handler) http.Handler { return next }
		registerWorkflowRoutes(router, handler.NewWorkflowHandler(nil, nil, logger.NewNop()), as, nil, noop)
		rec := httptest.NewRecorder()
		router.(interface{ Handler() http.Handler }).Handler().ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader("{}")))
		return rec.Code, rec.Body.String()
	}
	writer := []string{string(permission.AutomationsRead), string(permission.AutomationsWrite)}
	for _, rt := range []struct{ method, path string }{
		{http.MethodPost, wf + "/publish"},
		{http.MethodPost, ver + "/approve"},
		{http.MethodPost, ver + "/rollback"},
		{http.MethodPut, wf + "/mode"},
		{http.MethodDelete, wf},
	} {
		if code, body := serve(writer, rt.method, rt.path); code != http.StatusForbidden {
			t.Errorf("write-only member: %s %s = %d %s, want 403", rt.method, rt.path, code, body)
		}
	}
	reader := []string{string(permission.AutomationsRead)}
	for _, rt := range []struct{ method, path string }{
		{http.MethodPut, wf + "/graph"},
		{http.MethodPost, wf + "/preview"},
		{http.MethodPost, wf + "/verify"},
		{http.MethodPost, wf + "/runs"},
	} {
		if code, body := serve(reader, rt.method, rt.path); code != http.StatusForbidden {
			t.Errorf("read-only member: %s %s = %d %s, want 403", rt.method, rt.path, code, body)
		}
	}
}
