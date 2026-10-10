package routes

import (
	"net/http"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/scanpolicy"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Scope entries under scan approval governance (RFC-072 §6), through the
// real routes: by default (Off) a widening takes effect without a second
// person, T2 included, but still needs the approval permission (a member's
// request waits); Strict brings back the approvals of RFC-054 §7; a
// platform override wins over the owner's choice; another organization
// keeps its own mode. No tenant route changes the platform override.
func TestScopeApprovalPolicy_TenantView_DB(t *testing.T) {
	h := newChangeAuditHarness(t, func(s *scopeapp.Service, sh *handler.ScopeHandler, db *postgres.DB) {
		log := logger.NewNop()
		ts := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
			tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
		sh.SetSettingsStore(ts)
		s.SetEntryPolicy(ts, postgres.NewMemberLifecycleRepository(db), nil)
		pol := scanpolicy.NewService(postgres.NewScanPolicyRepository(db), nil, nil, nil, nil, log)
		pol.SetSettings(ts)
		s.SetGovernance(pol)
	})
	org, other := h.tenant(), h.tenant()
	h.member(org, "owner")
	admin, member := h.member(org, "admin"), h.member(org, "member")
	otherAdmin := h.member(other, "admin")
	h.member(other, "owner")

	st := settingsOf(t, h.expect(admin, http.MethodGet, "/api/v1/scope/settings", "", http.StatusOK))
	if p, _ := st["approval_policy"].(map[string]any); p["scan_approval"] != "off" || p["source"] != "organization" || p["entries_need_approval"] != false {
		t.Fatalf("default: %v", st["approval_policy"])
	}
	e := settingsOf(t, h.expect(admin, http.MethodPost, "/api/v1/scope/targets",
		`{"target_type":"domain","pattern":"t2.policy.example.com","max_tier":"t2","expires_in_days":3,"reason":"pentest"}`, http.StatusCreated))
	if e["status"] != "active" || e["approvals_required"] != float64(0) {
		t.Fatalf("Off: a T2 entry takes effect without a second person: %v", e)
	}
	req := settingsOf(t, h.expect(member, http.MethodPost, "/api/v1/scope/targets",
		`{"target_type":"domain","pattern":"one.policy.example.com","reason":"need it","expires_in_days":3}`, http.StatusCreated))
	if req["status"] != "pending" {
		t.Fatalf("Off: a member's request took effect without an approver: %v", req)
	}

	// Strict: entries need approvals again (two administrators: one other).
	h.exec(`UPDATE tenants SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), '{scan_governance}', '{"mode":"strict"}') WHERE id = $1`, org)
	st = settingsOf(t, h.expect(member, http.MethodGet, "/api/v1/scope/settings", "", http.StatusOK))
	if p, _ := st["approval_policy"].(map[string]any); p["scan_approval"] != "strict" || p["entries_need_approval"] != true {
		t.Fatalf("strict: %v", st["approval_policy"])
	}
	e = settingsOf(t, h.expect(admin, http.MethodPost, "/api/v1/scope/targets",
		`{"target_type":"domain","pattern":"*.strict.example.com"}`, http.StatusCreated))
	if e["status"] != "pending" {
		t.Fatalf("Strict: a widening took effect without a second person: %v", e)
	}

	// The platform forces Off: the override wins over the owner's Strict.
	h.exec(`UPDATE tenants SET scan_approval_policy = 'off' WHERE id = $1`, org)
	st = settingsOf(t, h.expect(member, http.MethodGet, "/api/v1/scope/settings", "", http.StatusOK))
	if p, _ := st["approval_policy"].(map[string]any); p["scan_approval"] != "off" || p["source"] != "platform" {
		t.Fatalf("forced off: %v", st["approval_policy"])
	}
	e = settingsOf(t, h.expect(admin, http.MethodPost, "/api/v1/scope/targets",
		`{"target_type":"domain","pattern":"*.forced.example.com"}`, http.StatusCreated))
	if e["status"] != "active" {
		t.Fatalf("forced off: %v", e)
	}

	// The other organization keeps its own mode (Off) and is not forced.
	st = settingsOf(t, h.expect(otherAdmin, http.MethodGet, "/api/v1/scope/settings", "", http.StatusOK))
	if p, _ := st["approval_policy"].(map[string]any); p["scan_approval"] != "off" || p["source"] != "organization" {
		t.Fatalf("another organization took the override: %v", st["approval_policy"])
	}
	h.exec(`UPDATE tenants SET scan_approval_policy = 'strict' WHERE id = $1`, other)
	e = settingsOf(t, h.expect(otherAdmin, http.MethodPost, "/api/v1/scope/targets",
		`{"target_type":"domain","pattern":"*.other.example.com"}`, http.StatusCreated))
	if e["status"] != "pending" {
		t.Fatalf("forced strict: a widening took effect without a second person: %v", e)
	}
}
