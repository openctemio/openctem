package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/app/scanpolicy"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// "Require a verified domain before platform sensors scan a target"
// through the console routes (RFC-054 §8.1): off by default; any
// administrator reads; only a super admin changes it, with a reason and a
// fresh authenticator code; every change is audited; no tenant token
// reaches the route.
func TestAdminPlatformSensorProof_Routes_DB(t *testing.T) {
	h := newChainHarness(t, func(hs *Handlers, db *postgres.DB, console *adminconsole.Service) {
		log := logger.NewNop()
		svc := scanpolicy.NewService(postgres.NewScanPolicyRepository(db), postgres.NewAuditLogRepository(db), nil, nil, nil, log)
		hs.AdminScanPolicy = handler.NewAdminScanPolicyHandler(svc, console, log)
	})
	h.exec(`DELETE FROM platform_settings WHERE key = 'platform_sensor_proof'`)
	t.Cleanup(func() { h.exec(`DELETE FROM platform_settings WHERE key = 'platform_sensor_proof'`) })
	const path = "/api/v1/admin/settings/platform-sensor-proof"
	required := func(body string) (bool, bool) {
		var m map[string]any
		if json.Unmarshal([]byte(body), &m) != nil {
			return false, false
		}
		v, ok := m["required"].(bool)
		return v, ok
	}

	reader := h.newAdmin(admin.AdminRoleReadonly)
	reader.verify()
	if code, body := reader.do(http.MethodGet, path, nil, true); code != http.StatusOK {
		t.Fatalf("read: %d %s", code, body)
	} else if v, ok := required(body); !ok || v {
		t.Fatalf("default must be off: %s", body)
	}
	if code, _ := reader.do(http.MethodPut, path,
		map[string]any{"required": true, "reason": "x", "totp_code": reader.freshCode(true)}, true); code != http.StatusForbidden {
		t.Fatalf("a read-only administrator changed the setting: %d", code)
	}

	root := h.newAdmin(admin.AdminRoleSuperAdmin)
	root.verify()
	if code, _ := root.do(http.MethodPut, path, map[string]any{"required": true, "totp_code": root.freshCode(true)}, true); code != http.StatusBadRequest {
		t.Fatalf("no reason: %d", code)
	}
	root.closeStepUpWindow()
	if code, _ := root.do(http.MethodPut, path, map[string]any{"required": true, "reason": "public cloud"}, true); code != http.StatusUnauthorized {
		t.Fatalf("no code: %d", code)
	}
	// The route spent the code of the request refused for its reason.
	root.resetReplayGuard()
	code, body := root.do(http.MethodPut, path,
		map[string]any{"required": true, "version": 0, "reason": "public cloud", "totp_code": root.freshCode(true)}, true)
	if v, ok := required(body); code != http.StatusOK || !ok || !v {
		t.Fatalf("turn on: %d %s", code, body)
	}
	if _, body := reader.do(http.MethodGet, path, nil, true); !jsonHasBool(body, "required", true) {
		t.Fatalf("read after the change: %s", body)
	}
	var n int
	if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM admin_audit_logs WHERE admin_id = $1
		AND action = 'platform.platform_sensor_proof_changed' AND severity = 'critical'`, root.a.ID().String()).Scan(&n); err != nil || n != 1 {
		t.Fatalf("admin audit rows: %d %v, want 1", n, err)
	}

	// A tenant owner's token is not a console session.
	tok := h.tenantToken(h.organization(0), "owner")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, h.srv.URL+path, nil)
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

func jsonHasBool(body, key string, want bool) bool {
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return false
	}
	v, ok := m[key].(bool)
	return ok && v == want
}
