package routes

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	"github.com/openctemio/openctem/api/internal/app/platformai"
	"github.com/openctemio/openctem/api/internal/app/platformcaptcha"
	"github.com/openctemio/openctem/api/internal/app/platformsociallogin"
	"github.com/openctemio/openctem/api/internal/app/storagequota"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	routeCaptchaSecret = "0x4AAAAAAAroute-test-secret"
	routeAIKey         = "sk-route-test-key-0123456789"
)

func platformSettingsHarness(t *testing.T, envCaptcha bool) *chainHarness {
	t.Helper()
	keys := []string{platformcaptcha.SettingKey, platformai.SettingKey, storagequota.SettingKey, platformsociallogin.SettingKey}
	h := newChainHarness(t, func(hs *Handlers, db *postgres.DB, _ *adminconsole.Service) {
		cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
		if err != nil {
			t.Fatal(err)
		}
		repo := postgres.NewPlatformSettingRepository(db)
		rec := consolesetting.NewRecorder(postgres.NewAuditLogRepository(db), nil, "OpenCTEM", nil)
		ps := handler.NewAdminPlatformSettingsHandler(postgres.NewAdminRepository(db), logger.NewNop())
		envSite, envSecret := "", ""
		if envCaptcha {
			envSite, envSecret = "0x4AAAAAAAenv-site", "0x4AAAAAAAenv-secret"
		}
		ps.Captcha = platformcaptcha.NewService(repo, cipher, rec, envSite, envSecret, nil)
		ps.AI = platformai.NewService(repo, cipher, rec, false, "", "", nil)
		ps.StorageQuota = storagequota.NewService(repo, nil, rec, 20480)
		env := config.OAuthConfig{Enabled: true, FrontendCallbackURL: "https://ctem.example.com/auth/callback"}
		if envCaptcha {
			env.GitHub = config.OAuthProviderConfig{Enabled: true, ClientID: "env-github-id", ClientSecret: "env-github-secret"}
		}
		ps.SocialLogin = platformsociallogin.NewService(repo, cipher, rec, env, nil)
		hs.AdminPlatformSettings = ps
	})
	clear := func() {
		for _, k := range keys {
			h.exec(`DELETE FROM platform_settings WHERE key = $1`, k)
		}
	}
	clear()
	t.Cleanup(clear)
	return h
}

// A read-only administrator reads but cannot change; a super admin needs the
// step-up and a reason; the secret never comes back over the API and never
// reaches the audit log; the change is a critical audit row.
func TestAdminCaptchaSettings_Routes_DB(t *testing.T) {
	h := platformSettingsHarness(t, false)
	const path = "/api/v1/admin/settings/captcha"
	body := map[string]any{"site_key": "0x4AAAAAAAroute-site", "secret": routeCaptchaSecret, "reason": "protect sign-up", "version": 0}

	reader := h.newAdmin(admin.AdminRoleReadonly)
	reader.verify()
	if code, _ := reader.do(http.MethodGet, path, nil, false); code != http.StatusOK {
		t.Fatalf("read: %d", code)
	}
	reader.autoStepUp = true
	if code, _ := reader.do(http.MethodPut, path, body, true); code != http.StatusForbidden {
		t.Fatalf("a read-only administrator changed the CAPTCHA: %d", code)
	}

	super := h.newAdmin(admin.AdminRoleSuperAdmin)
	super.verify()
	super.closeStepUpWindow()
	if code, _ := super.do(http.MethodPut, path, body, true); code != http.StatusUnauthorized {
		t.Fatalf("without the step-up: %d", code)
	}
	super.autoStepUp = true
	noReason := map[string]any{"site_key": "0x4AAAAAAAroute-site", "secret": routeCaptchaSecret, "version": 0}
	if code, _ := super.do(http.MethodPut, path, noReason, true); code != http.StatusBadRequest {
		t.Fatalf("without a reason: %d", code)
	}
	code, resp := super.do(http.MethodPut, path, body, true)
	if code != http.StatusOK || strings.Contains(resp, routeCaptchaSecret) || !jsonHasBool(resp, "secret_set", true) {
		t.Fatalf("save: %d %s", code, resp)
	}
	code, resp = reader.do(http.MethodGet, path, nil, false)
	if code != http.StatusOK || strings.Contains(resp, routeCaptchaSecret) || !strings.Contains(resp, super.a.Email()) {
		t.Fatalf("read back: %d %s (secret hidden, author named)", code, resp)
	}
	var n, leaked int
	if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM admin_audit_logs WHERE admin_id = $1
		AND action = $2 AND severity = 'critical'`, super.a.ID().String(), platformcaptcha.ActionChanged).Scan(&n); err != nil || n != 1 {
		t.Fatalf("critical audit rows %d %v, want 1", n, err)
	}
	if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM admin_audit_logs
		WHERE admin_id = $1 AND (request_body::text LIKE '%' || $2 || '%')`, super.a.ID().String(), routeCaptchaSecret).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("the secret reached the audit log: %d %v", leaked, err)
	}
	var stored string
	if err := h.db.QueryRowContext(context.Background(), `SELECT value::text FROM platform_settings WHERE key = $1`, platformcaptcha.SettingKey).Scan(&stored); err != nil || strings.Contains(stored, routeCaptchaSecret) {
		t.Fatalf("the secret is stored in clear text: %v", err)
	}
}

// The environment pins the CAPTCHA keys: the console answers 409.
func TestAdminCaptchaSettings_LockedByEnvironment_DB(t *testing.T) {
	h := platformSettingsHarness(t, true)
	super := h.newAdmin(admin.AdminRoleSuperAdmin)
	super.verify()
	super.autoStepUp = true
	code, resp := super.do(http.MethodPut, "/api/v1/admin/settings/captcha",
		map[string]any{"site_key": "", "secret": "", "reason": "remove", "version": 0}, true)
	if code != http.StatusConflict || !strings.Contains(resp, string(handler.CodeSettingLockedByEnvironment)) {
		t.Fatalf("locked: %d %s", code, resp)
	}
	code, resp = super.do(http.MethodGet, "/api/v1/admin/settings/captcha", nil, false)
	if code != http.StatusOK || !jsonHasBool(resp, "locked_by_environment", true) || strings.Contains(resp, "env-secret") {
		t.Fatalf("read: %d %s", code, resp)
	}
}

// The platform AI key is write-only over the API; the storage quota default
// takes the route step-up.
func TestAdminAIAndQuotaSettings_Routes_DB(t *testing.T) {
	h := platformSettingsHarness(t, false)
	super := h.newAdmin(admin.AdminRoleSuperAdmin)
	super.verify()
	super.autoStepUp = true
	code, resp := super.do(http.MethodPut, "/api/v1/admin/settings/ai", map[string]any{"enabled": true, "provider": "claude",
		"model": "claude-sonnet-4", "api_key": routeAIKey, "reason": "offer platform AI", "version": 0}, true)
	if code != http.StatusOK || strings.Contains(resp, routeAIKey) || !jsonHasBool(resp, "key_set", true) {
		t.Fatalf("ai: %d %s", code, resp)
	}
	if code, resp = super.do(http.MethodGet, "/api/v1/admin/settings/ai", nil, false); code != http.StatusOK || strings.Contains(resp, routeAIKey) {
		t.Fatalf("ai read: %d", code)
	}
	code, resp = super.do(http.MethodPut, "/api/v1/admin/settings/storage-quota", map[string]any{"default_mb": 512, "version": 0}, true)
	if code != http.StatusOK || !strings.Contains(resp, `"default_mb":512`) || !strings.Contains(resp, `"source":"console"`) {
		t.Fatalf("quota: %d %s", code, resp)
	}
	reader := h.newAdmin(admin.AdminRoleReadonly)
	reader.verify()
	reader.autoStepUp = true
	if code, _ := reader.do(http.MethodPut, "/api/v1/admin/settings/storage-quota", map[string]any{"default_mb": 0, "version": 1}, true); code != http.StatusForbidden {
		t.Fatalf("a read-only administrator changed the quota: %d", code)
	}
}

const routeSocialSecret = "GOCSPX-route-test-secret-value"

// Social login: a read-only administrator reads but cannot change; a super
// admin needs the fresh step-up and a reason; the secret never comes back
// over the API and never reaches the audit log or the stored row in clear;
// the change is a critical audit row.
func TestAdminSocialLoginSettings_Routes_DB(t *testing.T) {
	h := platformSettingsHarness(t, false)
	const path = "/api/v1/admin/settings/social-login-providers"
	body := map[string]any{"enabled": true, "client_id": "1234-route.apps.googleusercontent.com", "secret": routeSocialSecret,
		"reason": "offer Google sign-in", "version": 0}

	reader := h.newAdmin(admin.AdminRoleReadonly)
	reader.verify()
	if code, resp := reader.do(http.MethodGet, path, nil, false); code != http.StatusOK || !strings.Contains(resp, "https://ctem.example.com/auth/callback/github") {
		t.Fatalf("read: %d %s", code, resp)
	}
	reader.autoStepUp = true
	if code, _ := reader.do(http.MethodPut, path+"/google", body, true); code != http.StatusForbidden {
		t.Fatalf("a read-only administrator changed social login: %d", code)
	}
	if code, _ := reader.do(http.MethodPost, path+"/google/test", map[string]any{}, true); code != http.StatusForbidden {
		t.Fatalf("a read-only administrator ran the check: %d", code)
	}

	super := h.newAdmin(admin.AdminRoleSuperAdmin)
	super.verify()
	super.closeStepUpWindow()
	if code, _ := super.do(http.MethodPut, path+"/google", body, true); code != http.StatusUnauthorized {
		t.Fatalf("without the step-up: %d", code)
	}
	super.autoStepUp = true
	noReason := map[string]any{"enabled": true, "client_id": "1234-route.apps.googleusercontent.com", "secret": routeSocialSecret, "version": 0}
	if code, _ := super.do(http.MethodPut, path+"/google", noReason, true); code != http.StatusBadRequest {
		t.Fatalf("without a reason: %d", code)
	}
	if code, _ := super.do(http.MethodPut, path+"/gitlab", body, true); code != http.StatusBadRequest {
		t.Fatalf("unknown provider: %d", code)
	}
	code, resp := super.do(http.MethodPut, path+"/google", body, true)
	if code != http.StatusOK || strings.Contains(resp, routeSocialSecret) || !strings.Contains(resp, `"secret_set":true`) {
		t.Fatalf("save: %d %s", code, resp)
	}
	code, resp = reader.do(http.MethodGet, path, nil, false)
	if code != http.StatusOK || strings.Contains(resp, routeSocialSecret) || !strings.Contains(resp, super.a.Email()) {
		t.Fatalf("read back: %d %s (secret hidden, author named)", code, resp)
	}
	var n, leaked int
	if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM admin_audit_logs WHERE admin_id = $1
		AND action = $2 AND severity = 'critical'`, super.a.ID().String(), platformsociallogin.ActionChanged).Scan(&n); err != nil || n != 1 {
		t.Fatalf("critical audit rows %d %v, want 1", n, err)
	}
	if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM admin_audit_logs
		WHERE admin_id = $1 AND (request_body::text LIKE '%' || $2 || '%')`, super.a.ID().String(), routeSocialSecret).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("the secret reached the audit log: %d %v", leaked, err)
	}
	var stored string
	if err := h.db.QueryRowContext(context.Background(), `SELECT value::text FROM platform_settings WHERE key = $1`, platformsociallogin.SettingKey).Scan(&stored); err != nil || strings.Contains(stored, routeSocialSecret) {
		t.Fatalf("the secret is stored in clear text: %v", err)
	}
}

// The client check never sends the stored secret with another client ID, and
// it is bounded like a sign-in attempt.
func TestAdminSocialLoginCheck_StoredSecretAndRateLimit_DB(t *testing.T) {
	h := platformSettingsHarness(t, false)
	const path = "/api/v1/admin/settings/social-login-providers"
	super := h.newAdmin(admin.AdminRoleSuperAdmin)
	super.verify()
	super.autoStepUp = true
	save := map[string]any{"enabled": true, "client_id": "1234-route.apps.googleusercontent.com", "secret": routeSocialSecret,
		"reason": "offer Google sign-in", "version": 0}
	if code, resp := super.do(http.MethodPut, path+"/google", save, true); code != http.StatusOK {
		t.Fatalf("save: %d %s", code, resp)
	}
	other := map[string]any{"client_id": "9999-other.apps.googleusercontent.com"}
	if code, resp := super.do(http.MethodPost, path+"/google/test", other, true); code != http.StatusBadRequest || strings.Contains(resp, routeSocialSecret) {
		t.Fatalf("another client ID with the stored secret: %d %s", code, resp)
	}
	limited := false
	for i := 0; i < 12 && !limited; i++ {
		code, _ := super.do(http.MethodPost, path+"/google/test", other, true)
		limited = code == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("the client check is not rate limited")
	}
}

// The environment pins a provider: the console answers 409 for it and still
// manages the others; the environment secret is never shown.
func TestAdminSocialLoginSettings_LockedByEnvironment_DB(t *testing.T) {
	h := platformSettingsHarness(t, true)
	super := h.newAdmin(admin.AdminRoleSuperAdmin)
	super.verify()
	super.autoStepUp = true
	const path = "/api/v1/admin/settings/social-login-providers"
	code, resp := super.do(http.MethodPut, path+"/github", map[string]any{"enabled": false, "reason": "off", "version": 0}, true)
	if code != http.StatusConflict || !strings.Contains(resp, string(handler.CodeSettingLockedByEnvironment)) {
		t.Fatalf("locked: %d %s", code, resp)
	}
	code, resp = super.do(http.MethodGet, path, nil, false)
	if code != http.StatusOK || !strings.Contains(resp, `"locked_by_environment":true`) || strings.Contains(resp, "env-github-secret") {
		t.Fatalf("read: %d %s", code, resp)
	}
}
