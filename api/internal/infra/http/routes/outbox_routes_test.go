package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// The notification outbox and the per-channel delivery history hold every
// event of the tenant (finding messages, asset names, owner emails) without
// data scope. Members and viewers hold notifications:read for their own
// in-app notices, which used to open this stream too; now only channel
// managers (integrations:manage) reach it. Research doc 15, L-03.
func TestOutboxRoutes_ChannelManagersOnly(t *testing.T) {
	const outboxID = "01a0f6e2-35a7-7cae-af10-874c1481fe6e"
	routes := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/notification-outbox/"},
		{http.MethodGet, "/api/v1/notification-outbox/stats"},
		{http.MethodGet, "/api/v1/notification-outbox/" + outboxID},
		{http.MethodPost, "/api/v1/notification-outbox/" + outboxID + "/retry"},
		{http.MethodDelete, "/api/v1/notification-outbox/" + outboxID},
		{http.MethodGet, "/api/v1/integrations/" + outboxID + "/notification-events"},
	}

	strs := func(perms []permission.Permission) []string {
		out := make([]string, len(perms))
		for i, p := range perms {
			out[i] = p.String()
		}
		return out
	}
	callers := []struct {
		name    string
		admin   bool
		perms   []string
		allowed bool
	}{
		{"member", false, strs(permission.GetPermissionsForRole(tenant.RoleMember)), false},
		{"viewer", false, strs(permission.GetPermissionsForRole(tenant.RoleViewer)), false},
		{"custom role with every notifications permission only", false, []string{
			permission.NotificationsRead.String(), permission.NotificationsWrite.String(),
			permission.NotificationsDelete.String(), permission.IntegrationsRead.String(),
		}, false},
		{"channel manager", false, []string{
			permission.NotificationsRead.String(), permission.NotificationsWrite.String(),
			permission.NotificationsDelete.String(), permission.IntegrationsManage.String(),
		}, true},
		{"admin", true, nil, true},
	}

	passThrough := Middleware(func(next http.Handler) http.Handler { return next })
	for _, c := range callers {
		router := infrahttp.NewChiRouter()
		auth := Middleware(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := context.WithValue(r.Context(), middleware.IsAdminKey, c.admin)
				ctx = context.WithValue(ctx, middleware.TenantIDKey, "01a0f6e2-35a7-7cae-af10-874c1481fe6f")
				ctx = context.WithValue(ctx, middleware.PermissionsKey, c.perms)
				next.ServeHTTP(w, r.WithContext(ctx))
			})
		})
		// Nil services: a request that passes the gate panics in the
		// handler, which is how "reached" is observed.
		registerOutboxRoutes(router, handler.NewOutboxHandler(nil, logger.NewNop()), auth, nil)
		registerIntegrationRoutes(router, handler.NewIntegrationHandler(nil, validator.New(), logger.NewNop()), nil, nil, auth, nil, passThrough)
		mux := router.(interface{ Handler() http.Handler }).Handler()

		for _, rt := range routes {
			t.Run(c.name+" "+rt.method+" "+rt.path, func(t *testing.T) {
				reached := false
				rec := httptest.NewRecorder()
				func() {
					defer func() {
						if recover() != nil {
							reached = true
						}
					}()
					mux.ServeHTTP(rec, httptest.NewRequest(rt.method, rt.path, nil))
				}()
				if !reached && rec.Code != http.StatusForbidden {
					reached = true // answered by the handler without panicking
				}
				if reached != c.allowed {
					t.Errorf("reached handler = %v (status %d), want %v", reached, rec.Code, c.allowed)
				}
			})
		}
	}
}
