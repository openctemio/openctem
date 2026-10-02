package handler

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// GET /api/v1/tenants and GET /api/v1/tenants/{tenant} are open to every
// member, viewer included, and returned the raw settings map. Secrets kept in
// tenant settings must never come back through them.
func TestTenantResponse_RedactsSecretSettings(t *testing.T) {
	const webhookSecret = "whsec-test-0123456789abcdef"
	const aiKey = "sk-ant-encrypted-or-not-0123456789"

	tn, err := tenant.NewTenant("Acme", "acme", "u1")
	if err != nil {
		t.Fatal(err)
	}
	tn.SetSetting("api", map[string]any{
		"api_key_enabled": true,
		"webhook_url":     "https://hooks.example.test/x",
		"webhook_secret":  webhookSecret,
		"webhook_events":  []any{"finding.created"},
	})
	tn.SetSetting("ai", map[string]any{"mode": "byok", "provider": "claude", "api_key": aiKey, "monthly_token_limit": 1000})
	tn.SetSetting("general", map[string]any{"timezone": "UTC"})

	raw, err := json.Marshal(toTenantResponse(tn))
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, secret := range []string{webhookSecret, aiKey} {
		if strings.Contains(body, secret) {
			t.Errorf("tenant response leaks a secret setting: %s", body)
		}
	}

	var resp struct {
		Settings map[string]map[string]any `json:"settings"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Settings["api"]["webhook_secret_configured"] != true || resp.Settings["ai"]["api_key_configured"] != true {
		t.Errorf("expected configured flags, got %v / %v", resp.Settings["api"], resp.Settings["ai"])
	}
	if resp.Settings["api"]["webhook_url"] != "https://hooks.example.test/x" || resp.Settings["general"]["timezone"] != "UTC" ||
		resp.Settings["ai"]["monthly_token_limit"] != float64(1000) {
		t.Errorf("non-secret settings must be kept: %v", resp.Settings)
	}

	// The entity itself is untouched: the server still needs the secret.
	if api, _ := tn.GetSetting("api"); api.(map[string]any)["webhook_secret"] != webhookSecret {
		t.Error("redaction must not modify the tenant's own settings")
	}
}

func TestTenantResponse_UnsetSecretsReportNotConfigured(t *testing.T) {
	tn, err := tenant.NewTenant("Acme", "acme", "u1")
	if err != nil {
		t.Fatal(err)
	}
	tn.SetSetting("api", map[string]any{"webhook_url": "", "webhook_secret": ""})
	raw, _ := json.Marshal(toTenantResponse(tn))
	if !strings.Contains(string(raw), `"webhook_secret_configured":false`) || strings.Contains(string(raw), `"webhook_secret":`) {
		t.Errorf("unexpected: %s", raw)
	}
}
