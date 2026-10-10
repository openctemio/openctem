package routes

import (
	"net/http"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/scangov"
	"github.com/openctemio/openctem/api/internal/app/scanpolicy"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The scan approval settings through the real routes (RFC-073 §4): Off by
// default; only an owner changes the mode, with a reason; turning it on
// seeds the Light preset; an administrator edits the rules, a member reads
// them and edits nothing; a platform-forced mode refuses the owner; another
// organization keeps its own settings.
func TestScanGovernanceSettings_Routes_DB(t *testing.T) {
	changeAuditExtraHandlers = func(hs *Handlers, db *postgres.DB) {
		log := logger.NewNop()
		ts := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
			tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
		pol := scanpolicy.NewService(postgres.NewScanPolicyRepository(db), nil, nil, nil, nil, log)
		pol.SetSettings(ts)
		hs.ScanGovernance = handler.NewScanGovernanceHandler(scangov.NewService(pol, ts, log), log)
	}
	t.Cleanup(func() { changeAuditExtraHandlers = nil })
	h := newChangeAuditHarness(t)
	org, other := h.tenant(), h.tenant()
	owner, admin, member := h.member(org, "owner"), h.member(org, "admin"), h.member(org, "member")
	otherOwner := h.member(other, "owner")
	const base = "/api/v1/organization/settings/scan-governance"

	st := settingsOf(t, h.expect(member, http.MethodGet, base, "", http.StatusOK))
	if st["mode"] != "off" || st["source"] != "organization" || st["scope_entries_need_approval"] != false {
		t.Fatalf("default: %v", st)
	}

	h.expect(admin, http.MethodPut, base+"/mode", `{"mode":"on","reason":"x"}`, http.StatusForbidden)
	h.expect(member, http.MethodPut, base+"/mode", `{"mode":"on","reason":"x"}`, http.StatusForbidden)
	h.expect(owner, http.MethodPut, base+"/mode", `{"mode":"on"}`, http.StatusBadRequest)
	h.expect(owner, http.MethodPut, base+"/mode", `{"mode":"loud","reason":"x"}`, http.StatusBadRequest)
	st = settingsOf(t, h.expect(owner, http.MethodPut, base+"/mode", `{"mode":"on","reason":"risk appetite"}`, http.StatusOK))
	rules, _ := st["rules"].([]any)
	if st["mode"] != "on" || len(rules) != 1 {
		t.Fatalf("turning it on seeds the Light preset: %v", st)
	}

	body := `{"rules":[{"name":"Production","enabled":true,"conditions":{"min_intensity":"active","asset_tags":["production"]},"requirement":{"approvals":2}}],"reason":"CAB"}`
	h.expect(member, http.MethodPut, base+"/rules", body, http.StatusForbidden)
	h.expect(admin, http.MethodPut, base+"/rules", `{"rules":[{"name":"x","enabled":true,"requirement":{"approvals":5}}],"reason":"x"}`, http.StatusBadRequest)
	st = settingsOf(t, h.expect(admin, http.MethodPut, base+"/rules", body, http.StatusOK))
	if rules, _ = st["rules"].([]any); len(rules) != 1 || rules[0].(map[string]any)["name"] != "Production" {
		t.Fatalf("rules replaced: %v", st)
	}

	// Strict brings back scope-entry approvals.
	st = settingsOf(t, h.expect(owner, http.MethodPut, base+"/mode", `{"mode":"strict","reason":"audit"}`, http.StatusOK))
	if st["scope_entries_need_approval"] != true {
		t.Fatalf("strict: %v", st)
	}

	// Another organization is untouched.
	st = settingsOf(t, h.expect(otherOwner, http.MethodGet, base, "", http.StatusOK))
	if rules, _ = st["rules"].([]any); st["mode"] != "off" || len(rules) != 0 {
		t.Fatalf("another organization saw the settings: %v", st)
	}

	// The platform forces Off: the owner cannot choose another mode.
	h.exec(`UPDATE tenants SET scan_approval_policy = 'off' WHERE id = $1`, org)
	st = settingsOf(t, h.expect(owner, http.MethodGet, base, "", http.StatusOK))
	if st["mode"] != "off" || st["source"] != "platform" || st["organization_mode"] != "strict" {
		t.Fatalf("forced off: %v", st)
	}
	code, resp := h.do(owner, http.MethodPut, base+"/mode", `{"mode":"on","reason":"x"}`)
	if code != http.StatusForbidden || !jsonHas(resp, "code", "SCAN_APPROVAL_FORCED") {
		t.Fatalf("a forced mode was changed: %d %s", code, resp)
	}
}
