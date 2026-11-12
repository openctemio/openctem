package handler

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
)

// Creating a user with the admin RBAC role answered "role": "member" (the
// membership label). The response now carries the effective role.
func TestProvisionedUserResponse_ReportsEffectiveRole(t *testing.T) {
	u, err := userdom.NewProvisionedLocalUser("new-admin@example.test", "New Admin")
	if err != nil {
		t.Fatal(err)
	}
	m, err := tenantdom.NewMembership(u.ID(), shared.NewID(), tenantdom.RoleMember, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp := toProvisionedUserResponse(&tenant.ProvisionedUser{User: u, Membership: m, EffectiveRole: "admin"})
	if resp.Role != "admin" {
		t.Fatalf("role = %q, want admin", resp.Role)
	}
	resp = toProvisionedUserResponse(&tenant.ProvisionedUser{User: u, Membership: m})
	if resp.Role != "member" {
		t.Fatalf("without an effective role, role = %q, want the membership label", resp.Role)
	}
}

// Tenant audit rows written for a platform admin recorded the proxy's
// "ip:port" socket address. They now carry the resolved client IP.
func TestAdminAuditContext_RecordsClientIP(t *testing.T) {
	a, err := admin.NewAdminUser("ops@platform.example.test", "Ops", admin.AdminRoleOpsAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/api/v1/admin/tenants/x/users", nil)
	r.RemoteAddr = "198.51.100.23:47380"
	r = r.WithContext(context.WithValue(r.Context(), middleware.AdminUserKey, a))

	actx := adminAuditContext(r, "t1")
	if actx.ActorIP != "198.51.100.23" {
		t.Fatalf("actor ip = %q, want the client IP without the port", actx.ActorIP)
	}
	if actx.ActorEmail != "platform-admin:ops@platform.example.test" {
		t.Fatalf("actor email = %q", actx.ActorEmail)
	}
}
