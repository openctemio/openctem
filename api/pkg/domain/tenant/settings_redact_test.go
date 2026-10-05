package tenant

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactSettings_TypedAndNestedSecrets(t *testing.T) {
	in := map[string]any{
		// Typed values, as SetSetting may store them.
		"api": map[string]any{"api_key_enabled": true, "webhook_url": "https://h.test", "webhook_secret": "whsec-1"},
		"ai":  AISettings{Mode: "byok", APIKey: "enc:sk-1", MonthlyTokenLimit: 5},
		"integrations": []any{
			map[string]any{"name": "x", "client_secret": "cs-1", "password": nil},
		},
	}
	out := RedactSettings(in)
	raw, _ := json.Marshal(out)
	for _, s := range []string{"whsec-1", "enc:sk-1", "cs-1"} {
		if strings.Contains(string(raw), s) {
			t.Fatalf("secret %q survived: %s", s, raw)
		}
	}
	api := out["api"].(map[string]any)
	if api["webhook_secret_configured"] != true || api["api_key_enabled"] != true || api["webhook_url"] != "https://h.test" {
		t.Fatalf("api = %v", api)
	}
	ai := out["ai"].(map[string]any)
	if ai["api_key_configured"] != true || ai["monthly_token_limit"] != float64(5) {
		t.Fatalf("ai = %v", ai)
	}
	item := out["integrations"].([]any)[0].(map[string]any)
	if item["client_secret_configured"] != true || item["password_configured"] != false || item["name"] != "x" {
		t.Fatalf("nested = %v", item)
	}
	if in["api"].(map[string]any)["webhook_secret"] != "whsec-1" {
		t.Fatal("input modified")
	}
}

func TestIsSecretSettingKey(t *testing.T) {
	for k, want := range map[string]bool{
		"webhook_secret": true, "api_key": true, "smtp_password": true, "client_secret": true,
		"webhook_url": false, "api_key_enabled": true, "webhook_secret_configured": false, "timezone": false,
	} {
		if got := IsSecretSettingKey(k); got != want {
			t.Errorf("IsSecretSettingKey(%q) = %v, want %v", k, got, want)
		}
	}
}
