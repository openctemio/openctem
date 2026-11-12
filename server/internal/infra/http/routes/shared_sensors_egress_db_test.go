package routes

import (
	"context"
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

// The egress addresses of shared sensors through the console
// (docs/rfcs/RFC-100-shared-sensors.md §9): any administrator reads; only a
// super admin replaces them, with a reason and a fresh code (route-level
// step-up); private and other internal ranges are refused and nothing is
// stored; the change is a critical admin audit row; no tenant token reaches
// the console route.
func TestAdminSharedSensorsEgress_Routes_DB(t *testing.T) {
	h := newChainHarness(t, func(hs *Handlers, db *postgres.DB, console *adminconsole.Service) {
		log := logger.NewNop()
		svc := scanpolicy.NewService(postgres.NewScanPolicyRepository(db), postgres.NewAuditLogRepository(db), nil, nil, nil, log)
		hs.AdminScanPolicy = handler.NewAdminScanPolicyHandler(svc, console, log)
	})
	h.exec(`DELETE FROM platform_settings WHERE key = $1`, scanpolicy.SharedSensorsEgressKey)
	t.Cleanup(func() { h.exec(`DELETE FROM platform_settings WHERE key = $1`, scanpolicy.SharedSensorsEgressKey) })
	const path = "/api/v1/admin/settings/shared-sensors/egress"
	stored := func() int {
		var n int
		if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM platform_settings WHERE key = $1`,
			scanpolicy.SharedSensorsEgressKey).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	reader := h.newAdmin(admin.AdminRoleReadonly)
	reader.verify()
	code, body := reader.do(http.MethodGet, path, nil, true)
	if code != http.StatusOK || !strings.Contains(body, `"global":[]`) || !strings.Contains(body, `"regions":{}`) || !strings.Contains(body, `"version":0`) {
		t.Fatalf("nothing stored: %d %s", code, body)
	}
	// A read-only administrator may read but not change.
	if code, _ := reader.do(http.MethodPut, path,
		map[string]any{"global": []string{"203.0.113.1"}, "reason": "x", "totp_code": reader.freshCode(true)}, true); code != http.StatusForbidden {
		t.Fatalf("a read-only administrator changed the egress addresses: %d", code)
	}

	root := h.newAdmin(admin.AdminRoleSuperAdmin)
	root.verify()
	// The route confirms the code: a bad one is 401.
	if code, _ := root.do(http.MethodPut, path,
		map[string]any{"global": []string{"203.0.113.1"}, "reason": "x", "totp_code": "000000"}, true); code != http.StatusUnauthorized {
		t.Fatalf("bad code: %d", code)
	}
	// Private and internal ranges are refused, globally or in a region.
	for _, bad := range []map[string]any{
		{"global": []string{"10.0.0.5"}},
		{"global": []string{"203.0.113.1", "172.16.0.0/12"}},
		{"regions": map[string][]string{"eu": {"169.254.169.254"}}},
		{"regions": map[string][]string{"eu": {"fd00::1"}}},
		{"regions": map[string][]string{"eu west": {"203.0.113.1"}}},
		{"global": []string{"scanner.example.com"}},
	} {
		root.resetReplayGuard()
		bad["reason"], bad["totp_code"] = "x", root.freshCode(false)
		if code, body := root.do(http.MethodPut, path, bad, true); code != http.StatusBadRequest {
			t.Fatalf("%v accepted: %d %s", bad, code, body)
		}
	}
	if n := stored(); n != 0 {
		t.Fatalf("a refused list was stored (%d rows)", n)
	}
	// A reason is required.
	root.resetReplayGuard()
	if code, _ := root.do(http.MethodPut, path,
		map[string]any{"global": []string{"203.0.113.1"}, "reason": " ", "totp_code": root.freshCode(false)}, true); code != http.StatusBadRequest {
		t.Fatalf("no reason: %d", code)
	}
	root.resetReplayGuard()
	code, body = root.do(http.MethodPut, path, map[string]any{
		"global":  []string{"203.0.113.9", "203.0.113.9"},
		"regions": map[string][]string{"eu-west": {"198.51.100.0/24"}},
		"version": 0, "reason": "new scanner range", "totp_code": root.freshCode(false)}, true)
	if code != http.StatusOK || !strings.Contains(body, `"global":["203.0.113.9"]`) || !strings.Contains(body, `"eu-west":["198.51.100.0/24"]`) ||
		!strings.Contains(body, `"version":1`) {
		t.Fatalf("update: %d %s", code, body)
	}
	if _, body := reader.do(http.MethodGet, path, nil, true); !strings.Contains(body, `"203.0.113.9"`) {
		t.Fatalf("read back: %s", body)
	}
	// A stale version is refused.
	root.resetReplayGuard()
	if code, _ := root.do(http.MethodPut, path,
		map[string]any{"global": []string{}, "version": 0, "reason": "x", "totp_code": root.freshCode(false)}, true); code != http.StatusConflict {
		t.Fatalf("stale version: %d", code)
	}
	var n int
	if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM admin_audit_logs WHERE admin_id = $1
		AND action = $2 AND severity = 'critical'`, root.a.ID().String(), scanpolicy.ActionSharedSensorsEgressChanged).Scan(&n); err != nil || n != 1 {
		t.Fatalf("admin audit rows: %d %v, want 1", n, err)
	}

	// A tenant owner's token is not a console session.
	tok := h.tenantToken(h.organization(0), "owner")
	for _, m := range []string{http.MethodGet, http.MethodPut} {
		code, _ := bearerDo(t, h.srv.URL+path, tok, m, `{"global":["203.0.113.1"],"reason":"x"}`)
		if code != http.StatusUnauthorized && code != http.StatusForbidden {
			t.Fatalf("a tenant token reached %s %s: %d", m, path, code)
		}
	}
}
