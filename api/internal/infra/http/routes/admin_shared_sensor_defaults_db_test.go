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

// MANAGED_SERVICE changes defaults only (RFC-100 §6): on a hosted service
// the proof requirement reads on and internal zones read off until a value
// is stored; a stored value wins. Internal zones and the anomaly thresholds
// are changed only by a super admin with a reason and a fresh code, audited;
// no tenant token reaches the routes.
func TestAdminSharedSensorDefaults_Routes_DB(t *testing.T) {
	var svc *scanpolicy.Service
	h := newChainHarness(t, func(hs *Handlers, db *postgres.DB, console *adminconsole.Service) {
		log := logger.NewNop()
		svc = scanpolicy.NewService(postgres.NewScanPolicyRepository(db), postgres.NewAuditLogRepository(db), nil, nil, nil, log)
		svc.SetManagedService(true)
		hs.AdminScanPolicy = handler.NewAdminScanPolicyHandler(svc, console, log)
	})
	keys := `DELETE FROM platform_settings WHERE key IN ('platform_sensor_proof', 'shared_sensor_internal_zones', 'shared_sensor_anomaly_thresholds')`
	h.exec(keys)
	t.Cleanup(func() { h.exec(keys) })
	const (
		proofPath   = "/api/v1/admin/settings/platform-sensor-proof"
		zonesPath   = "/api/v1/admin/settings/shared-sensor-internal-zones"
		anomalyPath = "/api/v1/admin/settings/shared-sensor-anomaly"
	)

	reader := h.newAdmin(admin.AdminRoleReadonly)
	reader.verify()
	if _, body := reader.do(http.MethodGet, proofPath, nil, true); !jsonHasBool(body, "required", true) || !jsonHasBool(body, "default", true) {
		t.Fatalf("hosted proof default must read on: %s", body)
	}
	if _, body := reader.do(http.MethodGet, zonesPath, nil, true); !jsonHasBool(body, "allowed", false) || !jsonHasBool(body, "default", false) {
		t.Fatalf("hosted internal zones default must read off: %s", body)
	}
	if code, body := reader.do(http.MethodGet, anomalyPath, nil, true); code != http.StatusOK || !jsonHasNumber(body, "distinct_domains_per_day", 25) {
		t.Fatalf("anomaly defaults: %d %s", code, body)
	}
	if code, _ := reader.do(http.MethodPut, zonesPath,
		map[string]any{"allowed": true, "reason": "x", "totp_code": reader.freshCode(true)}, true); code != http.StatusForbidden {
		t.Fatalf("a read-only administrator changed internal zones: %d", code)
	}
	if code, _ := reader.do(http.MethodPut, anomalyPath,
		map[string]any{"distinct_domains_per_day": 1, "failures_per_day": 1, "deny_list_hits_per_day": 1, "reason": "x", "totp_code": reader.freshCode(true)}, true); code != http.StatusForbidden {
		t.Fatalf("a read-only administrator changed the thresholds: %d", code)
	}

	root := h.newAdmin(admin.AdminRoleSuperAdmin)
	root.verify()
	root.closeStepUpWindow()
	if code, _ := root.do(http.MethodPut, zonesPath, map[string]any{"allowed": true, "reason": "central pool"}, true); code != http.StatusUnauthorized {
		t.Fatalf("no code: %d", code)
	}
	root.resetReplayGuard()
	code, body := root.do(http.MethodPut, zonesPath,
		map[string]any{"allowed": true, "version": 0, "reason": "central pool", "totp_code": root.freshCode(true)}, true)
	if code != http.StatusOK || !jsonHasBool(body, "allowed", true) {
		t.Fatalf("turn on: %d %s", code, body)
	}
	// The stored value wins over the hosted default.
	if !svc.SharedSensorsInternalZonesAllowed(context.Background()) {
		t.Fatal("stored on must win over MANAGED_SERVICE")
	}
	root.resetReplayGuard()
	if code, _ := root.do(http.MethodPut, anomalyPath,
		map[string]any{"distinct_domains_per_day": -1, "failures_per_day": 1, "deny_list_hits_per_day": 1, "reason": "x", "totp_code": root.freshCode(true)}, true); code != http.StatusBadRequest {
		t.Fatalf("negative threshold: %d", code)
	}
	root.resetReplayGuard()
	code, body = root.do(http.MethodPut, anomalyPath,
		map[string]any{"distinct_domains_per_day": 10, "failures_per_day": 20, "deny_list_hits_per_day": 2, "version": 0, "reason": "tighter", "totp_code": root.freshCode(true)}, true)
	if code != http.StatusOK || !jsonHasNumber(body, "distinct_domains_per_day", 10) {
		t.Fatalf("thresholds: %d %s", code, body)
	}
	var n int
	if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM admin_audit_logs WHERE admin_id = $1
		AND action IN ('platform.shared_sensor_internal_zones_changed', 'platform.shared_sensor_anomaly_thresholds_changed')
		AND severity = 'critical'`, root.a.ID().String()).Scan(&n); err != nil || n != 2 {
		t.Fatalf("admin audit rows: %d %v, want 2", n, err)
	}

	tok := h.tenantToken(h.organization(0), "owner")
	for _, p := range []string{zonesPath, anomalyPath} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, h.srv.URL+p, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
			t.Fatalf("a tenant token reached %s: %d", p, resp.StatusCode)
		}
	}
}

func jsonHasNumber(body, key string, want float64) bool {
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return false
	}
	v, ok := m[key].(float64)
	return ok && v == want
}
