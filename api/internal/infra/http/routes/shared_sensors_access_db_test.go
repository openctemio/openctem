package routes

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/app/scanpolicy"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Shared sensor access through the console (docs/rfcs/RFC-100-shared-sensors.md
// §5, §11): any administrator reads; only a super admin changes the instance
// setting or an organization's decision, with a reason and a fresh code;
// turning the switch on is refused while shared sensors are not ready, before
// the code is spent; no tenant token reaches the console routes.
func TestAdminSharedSensors_Routes_DB(t *testing.T) {
	h := newChainHarness(t, func(hs *Handlers, db *postgres.DB, console *adminconsole.Service) {
		log := logger.NewNop()
		svc := scanpolicy.NewService(postgres.NewScanPolicyRepository(db), postgres.NewAuditLogRepository(db), nil, nil, nil, log)
		hs.AdminScanPolicy = handler.NewAdminScanPolicyHandler(svc, console, log)
	})
	h.exec(`DELETE FROM platform_settings WHERE key = 'shared_sensors'`)
	t.Cleanup(func() { h.exec(`DELETE FROM platform_settings WHERE key = 'shared_sensors'`) })
	const path = "/api/v1/admin/settings/shared-sensors"

	reader := h.newAdmin(admin.AdminRoleReadonly)
	reader.verify()
	code, body := reader.do(http.MethodGet, path, nil, true)
	if code != http.StatusOK || !jsonHasBool(body, "enabled", false) || !jsonHasBool(body, "new_orgs", true) ||
		!jsonHasBool(body, "ready", scanpolicy.SharedSensorsReady()) {
		t.Fatalf("defaults: %d %s", code, body)
	}
	if code, _ := reader.do(http.MethodPut, path,
		map[string]any{"enabled": false, "new_orgs": false, "reason": "x", "totp_code": reader.freshCode(true)}, true); code != http.StatusForbidden {
		t.Fatalf("a read-only administrator changed the setting: %d", code)
	}

	root := h.newAdmin(admin.AdminRoleSuperAdmin)
	root.verify()
	if !scanpolicy.SharedSensorsReady() {
		// The switch cannot be turned on yet, whatever the code and reason;
		// the code is not spent and nothing is stored.
		onCode := root.freshCode(true)
		code, body := root.do(http.MethodPut, path,
			map[string]any{"enabled": true, "new_orgs": true, "reason": "go live", "totp_code": onCode}, true)
		if code != http.StatusConflict || !strings.Contains(body, "SHARED_SENSORS_NOT_READY") ||
			!strings.Contains(body, scanpolicy.ReasonSharedSensorsNotReady) || strings.Contains(strings.ToLower(body), "edition") {
			t.Fatalf("switch on with the gate closed: %d %s", code, body)
		}
		var n int
		if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM platform_settings WHERE key = 'shared_sensors'`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("refused switch-on stored a setting: %d %v", n, err)
		}
		// The same code still works for an allowed change.
		code, body = root.do(http.MethodPut, path,
			map[string]any{"enabled": false, "new_orgs": false, "version": 0, "reason": "per organization", "totp_code": onCode}, true)
		if code != http.StatusOK || !jsonHasBool(body, "new_orgs", false) {
			t.Fatalf("new_orgs off with the unspent code: %d %s", code, body)
		}
	}
	var n int
	if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM admin_audit_logs WHERE admin_id = $1
		AND action = 'platform.shared_sensors_changed' AND severity = 'critical'`, root.a.ID().String()).Scan(&n); err != nil || n != 1 {
		t.Fatalf("admin audit rows: %d %v, want 1", n, err)
	}

	// The decision for one organization: deny, read back, unknown is 404.
	org, other := h.organization(0), h.organization(0)
	orgPath := "/api/v1/admin/tenants/" + org + "/shared-sensors"
	if code, body := reader.do(http.MethodGet, orgPath, nil, true); code != http.StatusOK || !jsonHas(body, "access", "") {
		t.Fatalf("no decision: %d %s", code, body)
	}
	if code, _ := reader.do(http.MethodPut, orgPath,
		map[string]any{"access": "deny", "reason": "x", "totp_code": reader.freshCode(false)}, true); code != http.StatusForbidden {
		t.Fatalf("a read-only administrator set a decision: %d", code)
	}
	if code, _ := root.do(http.MethodPut, orgPath, map[string]any{"access": "maybe", "reason": "x", "totp_code": "000000"}, true); code != http.StatusBadRequest {
		t.Fatalf("invalid decision: %d", code)
	}
	root.resetReplayGuard()
	if code, body := root.do(http.MethodPut, orgPath,
		map[string]any{"access": "deny", "reason": "data residency", "totp_code": root.freshCode(false)}, true); code != http.StatusOK {
		t.Fatalf("deny: %d %s", code, body)
	}
	if _, body := reader.do(http.MethodGet, orgPath, nil, true); !jsonHas(body, "access", "deny") {
		t.Fatalf("read after deny: %s", body)
	}
	// Another organization is untouched.
	if _, body := reader.do(http.MethodGet, "/api/v1/admin/tenants/"+other+"/shared-sensors", nil, true); !jsonHas(body, "access", "") {
		t.Fatalf("another organization changed: %s", body)
	}
	if code, _ := reader.do(http.MethodGet, "/api/v1/admin/tenants/00000000-0000-0000-0000-00000000dead/shared-sensors", nil, true); code != http.StatusNotFound {
		t.Fatalf("unknown organization: %d", code)
	}

	// A tenant owner's token is not a console session.
	tok := h.tenantToken(org, "owner")
	for _, p := range []string{path, orgPath} {
		code, _ := bearerDo(t, h.srv.URL+p, tok, http.MethodPut, `{"enabled":true,"new_orgs":true,"access":"allow"}`)
		if code != http.StatusUnauthorized && code != http.StatusForbidden {
			t.Fatalf("a tenant token reached %s: %d", p, code)
		}
	}
}

// The organization owner's opt-out: owner and administrator read, only the
// owner changes it, and it is the caller's own organization only.
func TestOrganizationSharedSensors_OptOut_DB(t *testing.T) {
	h := newChainHarness(t)
	org, other := h.organization(0), h.organization(0)
	const path = "/api/v1/organization/settings/shared-sensors"
	owner, adminTok, member := h.tenantToken(org, "owner"), h.tenantToken(org, "admin"), h.tenantToken(org, "member")
	otherOwner := h.tenantToken(other, "owner")

	if code, body := bearerDo(t, h.srv.URL+path, adminTok, http.MethodGet, ""); code != http.StatusOK || !jsonHasBool(body, "opt_out", false) {
		t.Fatalf("admin read default: %d %s", code, body)
	}
	if code, _ := bearerDo(t, h.srv.URL+path, member, http.MethodGet, ""); code != http.StatusForbidden {
		t.Fatalf("member read: %d", code)
	}
	if code, _ := bearerDo(t, h.srv.URL+path, adminTok, http.MethodPut, `{"opt_out":true}`); code != http.StatusForbidden {
		t.Fatalf("an administrator changed the owner's choice: %d", code)
	}
	if code, _ := bearerDo(t, h.srv.URL+path, owner, http.MethodPut, `{"opt_out":true,"tenant_id":"`+other+`"}`); code != http.StatusBadRequest {
		t.Fatalf("unknown field accepted: %d", code)
	}
	if code, body := bearerDo(t, h.srv.URL+path, owner, http.MethodPut, `{"opt_out":true}`); code != http.StatusOK || !jsonHasBool(body, "opt_out", true) {
		t.Fatalf("owner opt-out: %d %s", code, body)
	}
	// Tenant audit row.
	var n int
	if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM audit_logs WHERE tenant_id = $1
		AND action = 'tenant.shared_sensors_updated'`, org).Scan(&n); err != nil || n != 1 {
		t.Fatalf("tenant audit rows: %d %v, want 1", n, err)
	}
	// The other organization is untouched.
	if code, body := bearerDo(t, h.srv.URL+path, otherOwner, http.MethodGet, ""); code != http.StatusOK || !jsonHasBool(body, "opt_out", false) {
		t.Fatalf("another organization changed: %d %s", code, body)
	}
}

func bearerDo(t *testing.T, url, token, method, body string) (int, string) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, url, r)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}
