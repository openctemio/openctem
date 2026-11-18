package routes

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/adminconsole"
	"github.com/openctemio/openctem/server/internal/app/consolesetting"
	"github.com/openctemio/openctem/server/internal/app/privatedestinations"
	"github.com/openctemio/openctem/server/internal/infra/http/handler"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/admin"
	"github.com/openctemio/openctem/server/pkg/httpsec"
	"github.com/openctemio/openctem/server/pkg/logger"
)

func privateDestinationsHarness(t *testing.T) *chainHarness {
	t.Helper()
	h := newChainHarness(t, func(hs *Handlers, db *postgres.DB, _ *adminconsole.Service) {
		rec := consolesetting.NewRecorder(postgres.NewAuditLogRepository(db), nil, "OpenCTEM", nil)
		ps := handler.NewAdminPlatformSettingsHandler(postgres.NewAdminRepository(db), logger.NewNop())
		ps.PrivateDestinations = privatedestinations.NewService(postgres.NewPlatformSettingRepository(db), rec, nil)
		hs.AdminPlatformSettings = ps
	})
	clear := func() {
		h.exec(`DELETE FROM platform_settings WHERE key = $1`, privatedestinations.SettingKey)
		_ = httpsec.SetConsolePrivateCIDRs(nil)
	}
	clear()
	t.Cleanup(clear)
	return h
}

// Only a platform owner with a fresh step-up and a reason changes the list;
// a read-only or operations administrator and a tenant owner's token never
// do; a saved list is applied to the guard at once; the change is one
// critical audit row with the old and new lists.
func TestAdminPrivateDestinations_Routes_DB(t *testing.T) {
	h := privateDestinationsHarness(t)
	const path = "/api/v1/admin/settings/private-destinations"
	body := map[string]any{"ranges": []map[string]string{{"cidr": "192.168.77.0/24", "note": "GitLab"}},
		"reason": "self-managed GitLab on the office network", "version": 0}

	if !httpsec.IsIPBlocked(net.ParseIP("192.168.77.10")) {
		t.Fatal("the range is open before the test")
	}

	// Every session signs in before any step-up spends the sign-in budget.
	owner := h.newAdmin(admin.AdminRoleSuperAdmin)
	owner.verify()
	reader := h.newAdmin(admin.AdminRoleReadonly)
	reader.verify()
	if code, resp := reader.do(http.MethodGet, path, nil, false); code != http.StatusOK || !strings.Contains(resp, `"server_ranges"`) {
		t.Fatalf("read: %d %s", code, resp)
	}
	for _, a := range []*consoleAdmin{reader} {
		a.autoStepUp = true
		if code, _ := a.do(http.MethodPut, path, body, true); code != http.StatusForbidden {
			t.Fatalf("%s changed the private destinations: %d", a.a.Role(), code)
		}
		if code, _ := a.do(http.MethodPost, path+"/test", map[string]string{"host": "192.168.77.10"}, true); code != http.StatusForbidden {
			t.Fatalf("%s tested a destination: %d", a.a.Role(), code)
		}
	}

	// A tenant owner's token is not a console session.
	org := h.organization(0)
	tok := h.tenantToken(org, "owner")
	for _, m := range []string{http.MethodGet, http.MethodPut} {
		if code := h.raw(m, path+"/", map[string]string{"Authorization": "Bearer " + tok}); code != http.StatusUnauthorized && code != http.StatusForbidden {
			t.Fatalf("tenant token reached %s %s: %d", m, path, code)
		}
	}

	owner.closeStepUpWindow()
	if code, _ := owner.do(http.MethodPut, path, body, true); code != http.StatusUnauthorized {
		t.Fatalf("without the step-up: %d", code)
	}
	owner.autoStepUp = true
	noReason := map[string]any{"ranges": body["ranges"], "version": 0}
	if code, _ := owner.do(http.MethodPut, path, noReason, true); code != http.StatusBadRequest {
		t.Fatalf("without a reason: %d", code)
	}
	for _, bad := range []string{"203.0.113.0/24", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fd00:ec2::254/128"} {
		b := map[string]any{"ranges": []map[string]string{{"cidr": "10.1.0.0/16"}, {"cidr": bad}}, "reason": "try", "version": 0}
		code, resp := owner.do(http.MethodPut, path, b, true)
		if code != http.StatusBadRequest || !strings.Contains(resp, string(handler.CodePrivateRangeInvalid)) || !strings.Contains(resp, `"index":1`) {
			t.Fatalf("%s accepted: %d %s", bad, code, resp)
		}
	}
	if !httpsec.IsIPBlocked(net.ParseIP("10.1.0.1")) {
		t.Fatal("a refused list opened its valid entries")
	}

	code, resp := owner.do(http.MethodPut, path, body, true)
	if code != http.StatusOK || !strings.Contains(resp, `"in_force":["192.168.77.0/24"]`) || !strings.Contains(resp, "GitLab") {
		t.Fatalf("save: %d %s", code, resp)
	}
	if httpsec.IsIPBlocked(net.ParseIP("192.168.77.10")) {
		t.Fatal("the saved range is not applied")
	}
	if !httpsec.IsIPBlocked(net.ParseIP("192.168.78.10")) {
		t.Fatal("an address outside the saved range is open")
	}

	var n int
	if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM admin_audit_logs WHERE admin_id = $1
		AND action = $2 AND severity = 'critical'
		AND request_body->'previous_ranges' = '[]'::jsonb
		AND request_body->'ranges'->0->>'cidr' = '192.168.77.0/24'
		AND request_body->>'reason' = 'self-managed GitLab on the office network'`,
		owner.a.ID().String(), privatedestinations.ActionChanged).Scan(&n); err != nil || n != 1 {
		t.Fatalf("critical audit rows with old and new lists %d %v, want 1", n, err)
	}

	// The test resolves and judges; an IP literal needs no lookup.
	code, resp = owner.do(http.MethodPost, path+"/test", map[string]string{"host": "192.168.77.10"}, true)
	if code != http.StatusOK || !strings.Contains(resp, `"verdict":"allowed_private"`) || !strings.Contains(resp, `"source":"console"`) {
		t.Fatalf("test opened: %d %s", code, resp)
	}
	code, resp = owner.do(http.MethodPost, path+"/test", map[string]string{"host": "169.254.169.254"}, true)
	if code != http.StatusOK || !strings.Contains(resp, `"name_blocked":true`) {
		t.Fatalf("test metadata: %d %s", code, resp)
	}
	code, resp = owner.do(http.MethodPost, path+"/test", map[string]string{"host": "https://gitlab.example.com/x"}, true)
	if code != http.StatusBadRequest || !strings.Contains(resp, string(handler.CodeDestinationNotHost)) {
		t.Fatalf("test URL: %d %s", code, resp)
	}
}

// The destination test is bounded per administrator.
func TestAdminPrivateDestinations_TestRateLimited_DB(t *testing.T) {
	h := newChainHarness(t, func(hs *Handlers, db *postgres.DB, _ *adminconsole.Service) {
		rec := consolesetting.NewRecorder(postgres.NewAuditLogRepository(db), nil, "OpenCTEM", nil)
		ps := handler.NewAdminPlatformSettingsHandler(postgres.NewAdminRepository(db), logger.NewNop())
		ps.PrivateDestinations = privatedestinations.NewService(postgres.NewPlatformSettingRepository(db), rec, nil)
		hs.AdminPlatformSettings = ps
		hs.AdminDestinationTestLimiter = middleware.NewAdminMappingRateLimiter(middleware.AdminMappingRateLimitConfig{WriteRequestsPerMin: 2}, logger.NewNop())
	})
	owner := h.newAdmin(admin.AdminRoleSuperAdmin)
	owner.verify()
	owner.autoStepUp = true
	var last int
	for i := 0; i < 3; i++ {
		last, _ = owner.do(http.MethodPost, "/api/v1/admin/settings/private-destinations/test", map[string]string{"host": "10.9.9.9"}, true)
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("third test in a minute: %d, want 429", last)
	}
}

// An operations administrator (the day-to-day platform admin role) neither
// changes the list nor tests a destination: opening the platform's network
// is the platform owner's.
func TestAdminPrivateDestinations_OpsAdminRefused_DB(t *testing.T) {
	h := privateDestinationsHarness(t)
	const path = "/api/v1/admin/settings/private-destinations"
	ops := h.newAdmin(admin.AdminRoleOpsAdmin)
	ops.verify()
	ops.autoStepUp = true
	body := map[string]any{"ranges": []map[string]string{{"cidr": "192.168.77.0/24"}}, "reason": "r", "version": 0}
	if code, _ := ops.do(http.MethodPut, path, body, true); code != http.StatusForbidden {
		t.Fatalf("ops admin changed the private destinations: %d", code)
	}
	if code, _ := ops.do(http.MethodPost, path+"/test", map[string]string{"host": "10.1.1.1"}, true); code != http.StatusForbidden {
		t.Fatalf("ops admin tested a destination: %d", code)
	}
	if !httpsec.IsIPBlocked(net.ParseIP("192.168.77.10")) {
		t.Fatal("a refused change opened the range")
	}
}
