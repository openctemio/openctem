package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/app/scanpolicy"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The platform scan approval policy through the console routes (RFC-072
// §5): any administrator reads; only a super admin changes it, with a
// reason and a fresh authenticator code; every change is in the admin audit
// log; an organization override wins over the default and forces the
// organization's mode; no tenant token reaches the routes.
func TestAdminScanPolicy_Routes_DB(t *testing.T) {
	h := newChainHarness(t, func(hs *Handlers, db *postgres.DB, console *adminconsole.Service) {
		log := logger.NewNop()
		svc := scanpolicy.NewService(postgres.NewScanPolicyRepository(db), postgres.NewAuditLogRepository(db), nil, nil, nil, log)
		hs.AdminScanPolicy = handler.NewAdminScanPolicyHandler(svc, console, log)
	})
	h.exec(`DELETE FROM platform_settings WHERE key = 'scan_approval_policy'`)
	t.Cleanup(func() { h.exec(`DELETE FROM platform_settings WHERE key = 'scan_approval_policy'`) })
	org := h.organization(0)

	reader := h.newAdmin(admin.AdminRoleReadonly)
	reader.verify()
	if code, body := reader.do(http.MethodGet, "/api/v1/admin/settings/scan-approval-policy", nil, true); code != http.StatusOK || !jsonHas(body, "policy", "tenant_controlled") {
		t.Fatalf("read default: %d %s", code, body)
	}
	if code, _ := reader.do(http.MethodPut, "/api/v1/admin/settings/scan-approval-policy",
		map[string]any{"policy": "off", "reason": "x", "totp_code": reader.freshCode(true)}, true); code != http.StatusForbidden {
		t.Fatalf("a read-only administrator changed the policy: %d", code)
	}

	root := h.newAdmin(admin.AdminRoleSuperAdmin)
	root.verify()
	if code, _ := root.do(http.MethodPut, "/api/v1/admin/settings/scan-approval-policy",
		map[string]any{"policy": "off", "totp_code": root.freshCode(true)}, true); code != http.StatusBadRequest {
		t.Fatalf("no reason: %d", code)
	}
	if code, _ := root.do(http.MethodPut, "/api/v1/admin/settings/scan-approval-policy",
		map[string]any{"policy": "off", "reason": "lab"}, true); code != http.StatusUnauthorized {
		t.Fatalf("no code: %d", code)
	}
	if code, body := root.do(http.MethodPut, "/api/v1/admin/settings/scan-approval-policy",
		map[string]any{"policy": "off", "reason": "lab deployment", "version": 0, "totp_code": root.freshCode(true)}, true); code != http.StatusOK || !jsonHas(body, "policy", "off") {
		t.Fatalf("set default: %d %s", code, body)
	}
	root.resetReplayGuard()
	path := "/api/v1/admin/tenants/" + org + "/scan-approval-policy"
	if code, body := root.do(http.MethodGet, path, nil, true); code != http.StatusOK || !jsonHas(body, "policy", "off") || !jsonHas(body, "source", "platform_default") || !jsonHas(body, "effective_mode", "off") {
		t.Fatalf("org follows the default: %d %s", code, body)
	}
	if code, body := root.do(http.MethodPut, path,
		map[string]any{"policy": "strict", "reason": "customer asked", "totp_code": root.freshCode(false)}, true); code != http.StatusOK ||
		!jsonHas(body, "policy", "strict") || !jsonHas(body, "source", "organization_override") || !jsonHas(body, "effective_mode", "strict") {
		t.Fatalf("org override: %d %s", code, body)
	}
	if code, _ := root.do(http.MethodGet, "/api/v1/admin/tenants/"+uuid.NewString()+"/scan-approval-policy", nil, true); code != http.StatusNotFound {
		t.Fatalf("unknown organization: %d", code)
	}

	var n int
	if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM admin_audit_logs WHERE admin_id = $1
		AND action IN ('platform.scan_approval_policy_changed', 'organization.scan_approval_policy_changed')`, root.a.ID().String()).Scan(&n); err != nil || n != 2 {
		t.Fatalf("admin audit rows: %d %v, want 2", n, err)
	}

	// A tenant owner's token is not a console session.
	tok := h.tenantToken(org, "owner")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.srv.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a tenant token reached the console route: %d", resp.StatusCode)
	}
}

func jsonHas(body, key, want string) bool {
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return false
	}
	v, _ := m[key].(string)
	return v == want
}
