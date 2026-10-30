package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func auditReqAs(role admin.AdminRole) *http.Request {
	now := time.Now()
	a := admin.Reconstitute(shared.NewID(), "a@x.io", "A", role, true,
		nil, nil, "", 0, nil, nil, "", now, nil, now)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit-logs/", nil)
	return r.WithContext(context.WithValue(r.Context(), middleware.AdminUserKey, a))
}

// A read-only administrator reads the action, actor, time and result of an
// audit row, never the network address, user agent or request body (support
// reasons, customer references). Operations administrators and above do.
func TestAuditDetailIsForOpsAdminAndAbove(t *testing.T) {
	row := &admin.AuditLog{
		ID: shared.NewID(), AdminEmail: "ann@corp.example", Action: "support.session_start",
		RequestMethod: "POST", RequestPath: "/api/v1/admin/support/grants",
		RequestBody: map[string]interface{}{"reason": "customer ref 4411"},
		IPAddress:   "203.0.113.7", UserAgent: "Mozilla/5.0", Success: true, CreatedAt: time.Now(),
	}
	for _, c := range []struct {
		role   admin.AdminRole
		detail bool
	}{
		{admin.AdminRoleReadonly, false},
		{admin.AdminRoleOpsAdmin, true},
		{admin.AdminRoleSuperAdmin, true},
	} {
		got := toAdminAuditLogResponse(row, canSeeAuditDetail(auditReqAs(c.role)))
		has := got.IPAddress != "" || got.UserAgent != "" || got.RequestBody != nil
		if has != c.detail {
			t.Errorf("%s: detail present = %v, want %v", c.role, has, c.detail)
		}
		if got.Action != row.Action || got.AdminEmail != row.AdminEmail || !got.Success || got.CreatedAt == "" {
			t.Errorf("%s: action, actor, time and result must always be returned: %+v", c.role, got)
		}
	}
	// No administrator on the context (a wiring mistake) fails closed.
	if canSeeAuditDetail(httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Error("a request without an administrator must not see audit detail")
	}
}
