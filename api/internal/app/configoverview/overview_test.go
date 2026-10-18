package configoverview

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type settingsMap map[string]platformsetting.State

func (m settingsMap) Get(_ context.Context, k string) (platformsetting.State, error) {
	if s, ok := m[k]; ok {
		return s, nil
	}
	return platformsetting.State{}, platformsetting.ErrNotFound
}
func (m settingsMap) CreateIfAbsent(context.Context, string, platformsetting.State) (bool, error) {
	return false, nil
}
func (m settingsMap) Update(context.Context, string, json.RawMessage, int, shared.ID, time.Time) (platformsetting.State, error) {
	return platformsetting.State{}, nil
}

type adminsMap map[string]*admin.AdminUser

func (m adminsMap) GetByID(_ context.Context, id shared.ID) (*admin.AdminUser, error) {
	if a, ok := m[id.String()]; ok {
		return a, nil
	}
	return nil, admin.ErrAdminNotFound
}

func find(t *testing.T, items []Item, key string) Item {
	t.Helper()
	for _, it := range items {
		if it.Key == key {
			return it
		}
	}
	t.Fatalf("no row %s", key)
	return Item{}
}

func testConfig() *config.Config {
	c := &config.Config{}
	c.App.URL = "https://ctem.example.test"
	c.Auth.SignupMode = "disabled"
	c.Auth.CaptchaTurnstileSecret = "0x-very-secret"
	c.Auth.CaptchaTurnstileSiteKey = "0x-site"
	c.AITriage.AnthropicAPIKey = "sk-secret-value"
	c.AdminAuditSink.URL = "https://sink.example.test/hook?token=abc"
	c.Storage.TenantQuotaMB = 20480
	c.Worker.VersionCheckEnabled = true
	return c
}

// A secret never leaves the overview: only whether it is set.
func TestSecretsAreNeverReturned(t *testing.T) {
	b := NewBuilder(testConfig(), nil, nil, func(string) (string, bool) { return "", true })
	items, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(items)
	for _, secret := range []string{"0x-very-secret", "sk-secret-value", "token=abc", "sink.example.test"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("the overview leaks %q", secret)
		}
	}
	turnstile := find(t, items, "CAPTCHA_TURNSTILE_SECRET")
	if !turnstile.Secret || turnstile.IsSet == nil || !*turnstile.IsSet || turnstile.Value != "" {
		t.Fatalf("turnstile row = %+v", turnstile)
	}
}

// Server settings say where they come from and that a change needs a restart.
func TestServerSettingSources(t *testing.T) {
	env := map[string]string{"APP_URL": "https://ctem.example.test", "OPENAI_API_KEY": "x"}
	b := NewBuilder(testConfig(), nil, nil, func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	items, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	app := find(t, items, "APP_URL")
	if app.Source != SourceEnvironment || !app.RestartRequired || app.Managed != ManagedServer || app.Value != "https://ctem.example.test" {
		t.Fatalf("APP_URL = %+v", app)
	}
	quota := find(t, items, "STORAGE_TENANT_QUOTA_MB")
	if quota.Source != SourceDefault || quota.Value != "20480" || !quota.Planned {
		t.Fatalf("quota = %+v", quota)
	}
	if ai := find(t, items, "AI_PLATFORM_API_KEY"); ai.Source != SourceEnvironment {
		t.Fatalf("any provider key set means environment: %+v", ai)
	}
}

// Console settings report console or default, who changed them and when,
// apply without a restart, and name their environment ceiling.
func TestConsoleSettings(t *testing.T) {
	actor, _ := admin.NewAdminUser("root@example.test", "Root", admin.AdminRoleSuperAdmin, nil)
	id := actor.ID()
	at := time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC)
	settings := settingsMap{
		"signup_policy": {Value: json.RawMessage(`{}`), Version: 3, Source: platformsetting.SourceConsole, UpdatedBy: &id, UpdatedAt: at},
		"email.smtp":    {Value: json.RawMessage(`{"password_encrypted":"zzz"}`), Version: 1, Source: platformsetting.SourceEnvironment, UpdatedAt: at},
	}
	b := NewBuilder(testConfig(), settings, adminsMap{id.String(): actor}, func(string) (string, bool) { return "", false })
	items, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	signup := find(t, items, "signup_policy")
	if signup.Source != SourceConsole || signup.ChangedBy != "root@example.test" || signup.ChangedAt == nil ||
		signup.RestartRequired || !signup.Ceiling || signup.EnvVar != "SIGNUP_MODE" || signup.Page != "/system/sign-up" {
		t.Fatalf("signup = %+v", signup)
	}
	if email := find(t, items, "email.smtp"); email.Source != SourceEnvironment || email.Value != "" {
		t.Fatalf("email = %+v", email)
	}
	if legal := find(t, items, "legal"); legal.Source != SourceDefault || legal.ChangedAt != nil {
		t.Fatalf("legal = %+v", legal)
	}
	raw, _ := json.Marshal(items)
	if strings.Contains(string(raw), "zzz") {
		t.Fatal("a stored console value leaked into the overview")
	}
}

// Health and Platform scanning each became one console page; a row must never
// link to a page that no longer exists.
func TestConsoleSettingPagesAreLive(t *testing.T) {
	removed := map[string]bool{
		"/operations":               true,
		"/system":                   true,
		"/system/platform-scanning": true,
		"/system/shared-sensors":    true,
	}
	for _, s := range consoleSettings {
		if removed[s.page] {
			t.Errorf("setting %s links to the removed page %s", s.key, s.page)
		}
	}
	for _, key := range []string{"platform_sensor_proof", "shared_sensors"} {
		found := false
		for _, s := range consoleSettings {
			if s.key == key {
				found = true
				if s.page != "/scanning/platform" {
					t.Errorf("%s page = %s, want /scanning/platform", key, s.page)
				}
			}
		}
		if !found {
			t.Errorf("setting %s missing", key)
		}
	}
}
