package routes

import (
	"net/http"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/app/scopepolicy"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The platform approval policy as a tenant sees it (RFC-054 §12.6): the mode
// in force is shown; under tenant_controlled only an owner changes the
// approval count and may set 0 for t2; under disabled a widening takes
// effect without a second person but still needs the approval permission;
// another organization keeps the default. No tenant route changes the mode.
func TestScopeApprovalPolicy_TenantView_DB(t *testing.T) {
	h := newChangeAuditHarness(t, func(s *scopeapp.Service, sh *handler.ScopeHandler, db *postgres.DB) {
		log := logger.NewNop()
		ts := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
			tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
		sh.SetSettingsStore(ts)
		s.SetEntryPolicy(ts, postgres.NewMemberLifecycleRepository(db), nil)
		s.SetApprovalPolicy(scopepolicy.NewService(postgres.NewScopePolicyRepository(db), nil, nil, nil, nil, log))
	})
	org, other := h.tenant(), h.tenant()
	owner, admin, member := h.member(org, "owner"), h.member(org, "admin"), h.member(org, "member")
	otherAdmin := h.member(other, "admin")
	h.member(other, "owner")

	st := settingsOf(t, h.expect(admin, http.MethodGet, "/api/v1/scope/settings", "", http.StatusOK))
	if p, _ := st["approval_policy"].(map[string]any); p["mode"] != "required" || p["source"] != "platform_default" {
		t.Fatalf("default policy: %v", st["approval_policy"])
	}

	h.exec(`UPDATE tenants SET scope_approval_policy = 'tenant_controlled' WHERE id = $1`, org)
	st = settingsOf(t, h.expect(member, http.MethodGet, "/api/v1/scope/settings", "", http.StatusOK))
	if p, _ := st["approval_policy"].(map[string]any); p["mode"] != "tenant_controlled" || p["source"] != "organization_override" {
		t.Fatalf("override: %v", st["approval_policy"])
	}
	code, body := h.do(admin, http.MethodPut, "/api/v1/scope/settings", `{"widening_approvals":0}`)
	if code != http.StatusForbidden || !jsonHas(body, "code", "OWNER_REQUIRED") {
		t.Fatalf("an administrator lowered the count under tenant_controlled: %d %s", code, body)
	}
	h.expect(owner, http.MethodPut, "/api/v1/scope/settings", `{"widening_approvals":0}`, http.StatusOK)
	e := settingsOf(t, h.expect(admin, http.MethodPost, "/api/v1/scope/targets",
		`{"target_type":"domain","pattern":"t2.policy.example.com","max_tier":"t2","expires_in_days":3,"reason":"pentest"}`, http.StatusCreated))
	if e["status"] != "active" || e["approvals_required"] != float64(0) {
		t.Fatalf("t2 entry with 0 approvals under tenant_controlled: %v", e)
	}
	// An administrator's other changes still save.
	h.expect(admin, http.MethodPut, "/api/v1/scope/settings", `{"widening_approvals":0,"one_off_max_days":10}`, http.StatusOK)

	// Disabled: no approval, but the permission still gates widening.
	h.exec(`UPDATE tenants SET scope_approval_policy = 'disabled' WHERE id = $1`, org)
	e = settingsOf(t, h.expect(admin, http.MethodPost, "/api/v1/scope/targets",
		`{"target_type":"domain","pattern":"*.disabled.example.com"}`, http.StatusCreated))
	if e["status"] != "active" {
		t.Fatalf("widening under disabled approvals: %v", e)
	}
	req := settingsOf(t, h.expect(member, http.MethodPost, "/api/v1/scope/targets",
		`{"target_type":"domain","pattern":"one.disabled.example.com","reason":"need it","expires_in_days":3}`, http.StatusCreated))
	if req["status"] != "pending" {
		t.Fatalf("a member's request took effect without an approver: %v", req)
	}

	// The other organization keeps the default and its own two-admin rule.
	st = settingsOf(t, h.expect(otherAdmin, http.MethodGet, "/api/v1/scope/settings", "", http.StatusOK))
	if p, _ := st["approval_policy"].(map[string]any); p["mode"] != "required" {
		t.Fatalf("another organization took the override: %v", st["approval_policy"])
	}
	e = settingsOf(t, h.expect(otherAdmin, http.MethodPost, "/api/v1/scope/targets",
		`{"target_type":"domain","pattern":"*.other.example.com"}`, http.StatusCreated))
	if e["status"] != "pending" {
		t.Fatalf("another organization lost its approval: %v", e)
	}
}
