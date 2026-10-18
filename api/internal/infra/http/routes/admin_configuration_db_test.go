package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/app/configoverview"
	"github.com/openctemio/openctem/api/internal/app/versioncheck"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The version check switch over the console routes: a super admin with the
// step-up turns it off and on without a restart; a read-only administrator
// cannot; VERSION_CHECK_ENABLED=false is a ceiling the console cannot raise;
// every switch is audited.
func TestAdminVersionCheckSwitch_Routes_DB(t *testing.T) {
	for _, envOn := range []bool{true, false} {
		h := newChainHarness(t, func(hs *Handlers, db *postgres.DB, _ *adminconsole.Service) {
			svc := versioncheck.New(postgres.NewVersionCheckRepository(db), versioncheck.Config{Enabled: envOn,
				Keys: []string{"00"}, Running: "v1.0.0"}, logger.NewNop())
			svc.SetSettings(postgres.NewPlatformSettingRepository(db))
			hs.AdminVersionCheck = handler.NewAdminVersionCheckHandler(svc, postgres.NewAuditLogRepository(db), logger.NewNop())
		})
		h.exec(`DELETE FROM platform_settings WHERE key = 'version_check'`)
		t.Cleanup(func() { h.exec(`DELETE FROM platform_settings WHERE key = 'version_check'`) })
		const path = "/api/v1/admin/version-check"

		reader := h.newAdmin(admin.AdminRoleReadonly)
		reader.verify()
		reader.autoStepUp = true
		if code, _ := reader.do(http.MethodPut, path+"/enabled", map[string]bool{"enabled": false}, true); code != http.StatusForbidden {
			t.Fatalf("env=%v: a read-only administrator switched the check: %d", envOn, code)
		}

		super := h.newAdmin(admin.AdminRoleSuperAdmin)
		super.verify()
		super.closeStepUpWindow()
		if code, _ := super.do(http.MethodPut, path+"/enabled", map[string]bool{"enabled": false}, true); code != http.StatusUnauthorized {
			t.Fatalf("env=%v: switch without the step-up: %d", envOn, code)
		}
		super.autoStepUp = true

		code, body := super.do(http.MethodPut, path+"/enabled", map[string]bool{"enabled": false}, true)
		if code != http.StatusOK || !jsonHasBool(body, "enabled", false) {
			t.Fatalf("env=%v: off: %d %s", envOn, code, body)
		}
		code, body = super.do(http.MethodPut, path+"/enabled", map[string]bool{"enabled": true}, true)
		if envOn {
			if code != http.StatusOK || !jsonHasBool(body, "enabled", true) || !jsonHasBool(body, "locked_by_environment", false) {
				t.Fatalf("on: %d %s", code, body)
			}
		} else if code != http.StatusConflict || !strings.Contains(body, "VERSION_CHECK_LOCKED_BY_ENVIRONMENT") {
			t.Fatalf("on under VERSION_CHECK_ENABLED=false: %d %s, want 409", code, body)
		}
		var n int
		if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM admin_audit_logs WHERE admin_id = $1
			AND action = 'version_check.switched'`, super.a.ID().String()).Scan(&n); err != nil || n != 2 {
			t.Fatalf("env=%v: audit rows %d %v, want 2", envOn, n, err)
		}
	}
}

// The Configuration overview: any administrator reads it; secrets are only
// set or not set; a console setting names who changed it.
func TestAdminConfiguration_Routes_DB(t *testing.T) {
	cfg := &config.Config{}
	cfg.Auth.CaptchaTurnstileSecret = "0x-route-test-secret"
	cfg.Auth.CaptchaTurnstileSiteKey = "0x-site"
	h := newChainHarness(t, func(hs *Handlers, db *postgres.DB, _ *adminconsole.Service) {
		hs.AdminConfiguration = handler.NewAdminConfigurationHandler(configoverview.NewBuilder(cfg,
			postgres.NewPlatformSettingRepository(db), postgres.NewAdminRepository(db),
			func(string) (string, bool) { return "", false }), logger.NewNop())
	})
	reader := h.newAdmin(admin.AdminRoleReadonly)
	reader.verify()
	code, body := reader.do(http.MethodGet, "/api/v1/admin/configuration", nil, false)
	if code != http.StatusOK {
		t.Fatalf("read: %d %s", code, body)
	}
	if strings.Contains(body, "0x-route-test-secret") {
		t.Fatal("the overview returned a secret")
	}
	var out handler.AdminConfigurationResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil || len(out.Data) == 0 {
		t.Fatalf("decode: %v %s", err, body)
	}
	for _, it := range out.Data {
		if it.Key == "CAPTCHA_TURNSTILE_SECRET" && (it.IsSet == nil || !*it.IsSet || it.Value != "") {
			t.Fatalf("turnstile row = %+v", it)
		}
	}
}
