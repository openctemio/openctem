package routes

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/adminconsole"
	"github.com/openctemio/openctem/server/internal/app/consolesetting"
	"github.com/openctemio/openctem/server/internal/app/vulnfeed"
	"github.com/openctemio/openctem/server/internal/app/vulnfeedsources"
	"github.com/openctemio/openctem/server/internal/infra/http/handler"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/admin"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// probeStub answers every test fetch as verified (no network in tests).
type probeStub struct{ calls int }

func (p *probeStub) Probe(_ context.Context, base string, mirrors []string) []vulnfeed.ProbeResult {
	p.calls++
	out := []vulnfeed.ProbeResult{{Origin: base, OK: true, Format: "v2", Sequence: 7}}
	for _, m := range mirrors {
		out = append(out, vulnfeed.ProbeResult{Origin: m, OK: true, Format: "v2", Sequence: 7})
	}
	return out
}

func vulnFeedSourcesHarness(t *testing.T, env vulnfeedsources.Env, relay bool) (*chainHarness, *probeStub) {
	t.Helper()
	probe := &probeStub{}
	h := newChainHarness(t, func(hs *Handlers, db *postgres.DB, _ *adminconsole.Service) {
		rec := consolesetting.NewRecorder(postgres.NewAuditLogRepository(db), nil, "OpenCTEM", nil)
		ps := handler.NewAdminPlatformSettingsHandler(postgres.NewAdminRepository(db), logger.NewNop())
		svc := vulnfeedsources.NewService(postgres.NewPlatformSettingRepository(db), rec, env, nil)
		svc.SetProber(probe)
		svc.SetRelayMode(func(context.Context) bool { return relay })
		ps.VulnFeedSources = svc
		hs.AdminPlatformSettings = ps
	})
	clear := func() { h.exec(`DELETE FROM platform_settings WHERE key = $1`, vulnfeedsources.SettingKey) }
	clear()
	t.Cleanup(clear)
	return h, probe
}

func feedEnv() vulnfeedsources.Env {
	return vulnfeedsources.Env{BaseURL: vulnfeed.DefaultBaseURL, RootKeyID: "SHA256:root", OfficialRootKeyID: "SHA256:root"}
}

// Only a platform owner with a fresh step-up and a reason changes the feed
// address; a read-only or operations administrator and a tenant owner's
// token never do; the change is one critical audit row with the old and new
// values; any administrator reads the setting.
func TestAdminVulnFeedSources_Routes_DB(t *testing.T) {
	h, probe := vulnFeedSourcesHarness(t, feedEnv(), false)
	const path = "/api/v1/admin/settings/vulnfeed-sources"
	body := map[string]any{"base_url": "https://feed.example.org/releases", "mirrors": []string{"https://mirror.example.org/vulnfeed"},
		"reason": "company mirror", "version": 0}

	owner := h.newAdmin(admin.AdminRoleSuperAdmin)
	owner.verify()
	reader := h.newAdmin(admin.AdminRoleReadonly)
	reader.verify()
	code, resp := reader.do(http.MethodGet, path, nil, false)
	if code != http.StatusOK || !strings.Contains(resp, `"root_official":true`) || !strings.Contains(resp, `"bundle_dir_set":false`) ||
		!strings.Contains(resp, `"source":"default"`) {
		t.Fatalf("read: %d %s", code, resp)
	}
	for _, a := range []*consoleAdmin{reader} {
		a.autoStepUp = true
		if code, _ := a.do(http.MethodPut, path, body, true); code != http.StatusForbidden {
			t.Fatalf("%s changed the feed address: %d", a.a.Role(), code)
		}
		if code, _ := a.do(http.MethodPost, path+"/test", map[string]any{}, true); code != http.StatusForbidden {
			t.Fatalf("%s ran the test fetch: %d", a.a.Role(), code)
		}
	}
	if probe.calls != 0 {
		t.Fatal("a refused caller reached the test fetch")
	}

	// A tenant owner's token is not a console session.
	org := h.organization(0)
	tok := h.tenantToken(org, "owner")
	for _, m := range []string{http.MethodGet, http.MethodPut} {
		if code := h.raw(m, path+"/", map[string]string{"Authorization": "Bearer " + tok}); code != http.StatusUnauthorized && code != http.StatusForbidden {
			t.Fatalf("tenant token reached %s %s: %d", m, path, code)
		}
	}

	// Without a fresh step-up, then without a reason, then an unsafe address.
	owner.closeStepUpWindow()
	if code, _ := owner.do(http.MethodPut, path, body, true); code != http.StatusUnauthorized {
		t.Fatalf("without the step-up: %d", code)
	}
	owner.autoStepUp = true
	if code, _ := owner.do(http.MethodPut, path, map[string]any{"base_url": body["base_url"], "version": 0}, true); code != http.StatusBadRequest {
		t.Fatalf("without a reason: %d", code)
	}
	for _, bad := range []string{"http://feed.example.org/r", "https://u:p@feed.example.org/r", "https://10.0.0.5/r", "https://feed.example.org/r?t=1"} {
		b := map[string]any{"base_url": bad, "reason": "try", "version": 0}
		if code, resp := owner.do(http.MethodPut, path, b, true); code != http.StatusBadRequest {
			t.Fatalf("%s accepted: %d %s", bad, code, resp)
		}
	}

	code, resp = owner.do(http.MethodPut, path, body, true)
	if code != http.StatusOK || !strings.Contains(resp, `"source":"console"`) || !strings.Contains(resp, `"base_url":"https://feed.example.org/releases"`) {
		t.Fatalf("save: %d %s", code, resp)
	}
	var n int
	if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM admin_audit_logs WHERE admin_id = $1
		AND action = $2 AND severity = 'critical'
		AND request_body->>'previous_release' = $3
		AND request_body->>'release' = 'https://feed.example.org/releases'
		AND request_body->'mirrors'->>0 = 'https://mirror.example.org/vulnfeed'
		AND request_body->>'reason' = 'company mirror'`,
		owner.a.ID().String(), vulnfeedsources.ActionChanged, vulnfeed.DefaultBaseURL).Scan(&n); err != nil || n != 1 {
		t.Fatalf("critical audit rows with old and new values %d %v, want 1", n, err)
	}

	// The test fetch runs for the owner, on the values in force or given.
	code, resp = owner.do(http.MethodPost, path+"/test", map[string]any{}, true)
	if code != http.StatusOK || !strings.Contains(resp, `"origin":"https://feed.example.org/releases"`) || probe.calls != 1 {
		t.Fatalf("test: %d %s", code, resp)
	}
	if code, _ := owner.do(http.MethodPost, path+"/test", map[string]any{"base_url": "https://127.0.0.1/r"}, true); code != http.StatusBadRequest || probe.calls != 1 {
		t.Fatalf("an internal address was tested: %d", code)
	}
}

// An operations administrator (the day-to-day platform admin role, which
// runs and switches the feeds) neither changes the feed address nor runs
// the test fetch: where the feed comes from is the platform owner's.
func TestAdminVulnFeedSources_OpsAdminRefused_DB(t *testing.T) {
	h, probe := vulnFeedSourcesHarness(t, feedEnv(), false)
	const path = "/api/v1/admin/settings/vulnfeed-sources"
	ops := h.newAdmin(admin.AdminRoleOpsAdmin)
	ops.verify()
	ops.autoStepUp = true
	body := map[string]any{"base_url": "https://feed.example.org/releases", "reason": "r", "version": 0}
	if code, _ := ops.do(http.MethodPut, path, body, true); code != http.StatusForbidden {
		t.Fatalf("ops admin changed the feed address: %d", code)
	}
	if code, _ := ops.do(http.MethodPost, path+"/test", map[string]any{}, true); code != http.StatusForbidden || probe.calls != 0 {
		t.Fatalf("ops admin ran the test fetch: %d", code)
	}
	var n int
	if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM platform_settings WHERE key = $1`, vulnfeedsources.SettingKey).Scan(&n); err != nil || n != 0 {
		t.Fatalf("stored rows %d %v", n, err)
	}
}

// The environment pins the address: the change is refused with the lock
// code; relay mode refuses the test fetch (the platform makes no outbound
// request).
func TestAdminVulnFeedSources_LockedAndRelay_DB(t *testing.T) {
	env := feedEnv()
	env.Pinned, env.RootKeyID = true, "SHA256:custom"
	h, probe := vulnFeedSourcesHarness(t, env, true)
	const path = "/api/v1/admin/settings/vulnfeed-sources"
	owner := h.newAdmin(admin.AdminRoleSuperAdmin)
	owner.verify()
	owner.autoStepUp = true
	code, resp := owner.do(http.MethodGet, path, nil, false)
	if code != http.StatusOK || !strings.Contains(resp, `"locked_by_environment":true`) || !strings.Contains(resp, `"root_official":false`) {
		t.Fatalf("read: %d %s", code, resp)
	}
	code, resp = owner.do(http.MethodPut, path, map[string]any{"base_url": "https://feed.example.org/r", "reason": "r", "version": 0}, true)
	if code != http.StatusConflict || !strings.Contains(resp, string(handler.CodeSettingLockedByEnvironment)) {
		t.Fatalf("locked: %d %s", code, resp)
	}
	code, resp = owner.do(http.MethodPost, path+"/test", map[string]any{}, true)
	if code != http.StatusConflict || !strings.Contains(resp, string(handler.CodeFeedTestUnavailable)) || !strings.Contains(resp, "relay_mode") || probe.calls != 0 {
		t.Fatalf("relay test: %d %s", code, resp)
	}
}
