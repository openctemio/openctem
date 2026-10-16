package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/app/instancezone"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type allowInternalZones struct{}

func (allowInternalZones) SharedSensorsInternalZonesAllowed(context.Context) bool { return true }

// Instance scan zones through the console routes (RFC-100 §6.1): any
// administrator reads; only a super admin with a reason and a fresh code
// creates, changes and assigns a zone; only shared sensors serve one; the
// lookup sees only the zones assigned to the asking organization, so the
// same range assigned to two organizations never mixes; no tenant token
// reaches the routes; every change is a critical admin audit row.
func TestAdminInstanceScanZones_Routes_DB(t *testing.T) {
	var svc *instancezone.Service
	h := newChainHarness(t, func(hs *Handlers, db *postgres.DB, console *adminconsole.Service) {
		log := logger.NewNop()
		svc = instancezone.NewService(postgres.NewInstanceScanZoneRepository(db), nil, allowInternalZones{}, postgres.NewAuditLogRepository(db), log)
		hs.AdminInstanceScanZone = handler.NewAdminInstanceScanZoneHandler(svc, console, log)
	})
	const path = "/api/v1/admin/instance-scan-zones"
	t.Cleanup(func() { h.exec(`DELETE FROM instance_scan_zones WHERE name LIKE 'itest-%'`) })

	orgA, orgB := h.organization(0), h.organization(1)
	shared1 := uuid.NewString()
	h.exec(`INSERT INTO sensors (id, tenant_id, name, type, status, health, execution_mode, api_key_hash, api_key_prefix, scope)
	        VALUES ($1, NULL, $2, 'worker', 'active', 'unknown', 'daemon', $3, 'octs_plt', 'instance')`, shared1, "plat-"+shared1[:8], "hash-"+shared1)
	t.Cleanup(func() { h.exec(`DELETE FROM sensors WHERE id = $1`, shared1) })
	orgSensor := uuid.NewString()
	h.exec(`INSERT INTO sensors (id, tenant_id, name, type, status, health, execution_mode, api_key_hash, api_key_prefix, scope)
	        VALUES ($1, $2, $3, 'worker', 'active', 'unknown', 'daemon', $4, 'octs_org', 'organization')`, orgSensor, orgA, "org-"+orgSensor[:8], "hash-"+orgSensor)
	t.Cleanup(func() { h.exec(`DELETE FROM sensors WHERE id = $1`, orgSensor) })

	reader := h.newAdmin(admin.AdminRoleReadonly)
	reader.verify()
	if code, body := reader.do(http.MethodGet, path, nil, true); code != http.StatusOK {
		t.Fatalf("read: %d %s", code, body)
	}
	if code, _ := reader.do(http.MethodPost, path, map[string]any{"name": "itest-r", "ranges": []string{"10.0.0.0/8"},
		"reason": "x", "totp_code": reader.freshCode(true)}, true); code != http.StatusForbidden {
		t.Fatalf("a read-only administrator created a zone: %d", code)
	}

	root := h.newAdmin(admin.AdminRoleSuperAdmin)
	root.verify()
	root.closeStepUpWindow()
	if code, _ := root.do(http.MethodPost, path, map[string]any{"name": "itest-a", "ranges": []string{"10.20.0.0/16"}, "reason": "x"}, true); code != http.StatusUnauthorized {
		t.Fatalf("no code: %d", code)
	}
	create := func(name string, ranges []string) string {
		t.Helper()
		root.resetReplayGuard()
		code, body := root.do(http.MethodPost, path, map[string]any{"name": name, "ranges": ranges,
			"reason": "central scanners", "totp_code": root.freshCode(true)}, true)
		if code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", name, code, body)
		}
		var z handler.InstanceScanZoneResponse
		_ = json.Unmarshal([]byte(body), &z)
		return z.ID
	}
	root.resetReplayGuard()
	if code, _ := root.do(http.MethodPost, path, map[string]any{"name": "itest-pub", "ranges": []string{"203.0.113.0/24"},
		"reason": "x", "totp_code": root.freshCode(true)}, true); code != http.StatusBadRequest {
		t.Fatalf("a public range was accepted: %d", code)
	}
	za := create("itest-a", []string{"10.20.0.0/16"})
	zb := create("itest-b", []string{"10.20.0.0/16"})

	put := func(p string, ids []string) int {
		t.Helper()
		root.resetReplayGuard()
		code, _ := root.do(http.MethodPut, p, map[string]any{"ids": ids, "reason": "assign", "totp_code": root.freshCode(true)}, true)
		return code
	}
	// Only a shared sensor serves a zone.
	if code := put(path+"/"+za+"/sensors", []string{orgSensor}); code != http.StatusBadRequest {
		t.Fatalf("an organization's sensor was added to a zone: %d", code)
	}
	for _, z := range []string{za, zb} {
		if code := put(path+"/"+z+"/sensors", []string{shared1}); code != http.StatusOK {
			t.Fatalf("set sensors: %d", code)
		}
	}
	if code := put(path+"/"+za+"/organizations", []string{orgA}); code != http.StatusOK {
		t.Fatalf("assign A: %d", code)
	}
	if code := put(path+"/"+zb+"/organizations", []string{orgB}); code != http.StatusOK {
		t.Fatalf("assign B: %d", code)
	}

	// The lookup tells the overlapping zones apart by organization.
	ctx := context.Background()
	idA, _ := shared.IDFromString(orgA)
	idB, _ := shared.IDFromString(orgB)
	got, err := svc.ZoneFor(ctx, idA, []string{"10.20.4.4"})
	if err != nil || got == nil || got.ID.String() != za {
		t.Fatalf("A routed to %v (%v), want %s", got, err, za)
	}
	got, _ = svc.ZoneFor(ctx, idB, []string{"10.20.4.4"})
	if got == nil || got.ID.String() != zb {
		t.Fatalf("B routed to %v, want %s", got, zb)
	}
	if got, _ := svc.ZoneFor(ctx, shared.NewID(), []string{"10.20.4.4"}); got != nil {
		t.Fatal("an unassigned organization got a zone")
	}
	// Unassigning A stops it at once.
	if code := put(path+"/"+za+"/organizations", []string{}); code != http.StatusOK {
		t.Fatalf("unassign: %d", code)
	}
	if got, _ := svc.ZoneFor(ctx, idA, []string{"10.20.4.4"}); got != nil {
		t.Fatal("A still routed after it was unassigned")
	}

	var n int
	if err := h.db.QueryRowContext(ctx, `SELECT count(*) FROM admin_audit_logs WHERE admin_id = $1
		AND action LIKE 'platform.instance_scan_zone_%' AND severity = 'critical'`, root.a.ID().String()).Scan(&n); err != nil || n < 6 {
		t.Fatalf("admin audit rows: %d %v, want at least 6", n, err)
	}

	tok := h.tenantToken(orgA, "owner")
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		req, _ := http.NewRequestWithContext(ctx, m, h.srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
			t.Fatalf("a tenant token reached %s %s: %d", m, path, resp.StatusCode)
		}
	}

	// Delete.
	root.resetReplayGuard()
	if code, _ := root.do(http.MethodDelete, path+"/"+zb, map[string]any{"reason": "retired", "totp_code": root.freshCode(true)}, true); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if got, _ := svc.ZoneFor(ctx, idB, []string{"10.20.4.4"}); got != nil {
		t.Fatal("deleted zone still routes")
	}
}
