package admin

import "testing"

func TestRedactSensitiveFieldsKeyRules(t *testing.T) {
	in := map[string]interface{}{
		"password": "a", "New_Password": "b", "client_secret": "c", "sharedSecret": "d",
		"signing_key": "e", "API_KEY": "f", "reset_token": "g", "code": "123456", "TOTP": "h",
		"recovery_code": "i", "recovery_codes": []interface{}{"x", "y"},
		"name": "kept", "keyword": "kept", "tokenizer": "kept", "country_code_note": "kept",
		"nested": map[string]interface{}{"inner_secret": "j", "label": "kept"},
		"list":   []interface{}{map[string]interface{}{"backup_key": "k", "id": "kept"}},
	}
	out := redactSensitiveFields(in)
	for _, k := range []string{"password", "New_Password", "client_secret", "sharedSecret", "signing_key", "API_KEY",
		"reset_token", "code", "TOTP", "recovery_code", "recovery_codes"} {
		if out[k] != "[REDACTED]" {
			t.Errorf("%s not redacted: %v", k, out[k])
		}
	}
	for _, k := range []string{"name", "keyword", "tokenizer", "country_code_note"} {
		if out[k] != "kept" {
			t.Errorf("%s must be kept: %v", k, out[k])
		}
	}
	if n := out["nested"].(map[string]interface{}); n["inner_secret"] != "[REDACTED]" || n["label"] != "kept" {
		t.Errorf("nested: %v", n)
	}
	l := out["list"].([]interface{})[0].(map[string]interface{})
	if l["backup_key"] != "[REDACTED]" || l["id"] != "kept" {
		t.Errorf("list: %v", l)
	}
	if in["password"] != "a" {
		t.Error("input must not be modified")
	}
}

// A webhook address is a bearer secret: the audit row keeps its origin only.
func TestRedactSensitiveFieldsKeepsOnlyTheOriginOfAddresses(t *testing.T) {
	in := map[string]interface{}{
		"url":         "https://hooks.example.com/services/T000/B000/XXXXSECRET?x=1",
		"webhook_url": "https://user:pw@chat.example.com/webhook/abc",
		"issuer_url":  "https://idp.example.com/",
		"terms_url":   "https://example.com/terms",
		"base_url":    "not a url",
		"note_url":    "",
		"name":        "https://kept.example.com/path",
		"nested":      map[string]interface{}{"url": "https://hooks.example.com/secret"},
	}
	out := redactSensitiveFields(in)
	want := map[string]string{
		"url":         "https://hooks.example.com/[REDACTED]",
		"webhook_url": "https://chat.example.com/[REDACTED]",
		"issuer_url":  "https://idp.example.com",
		"terms_url":   "https://example.com/[REDACTED]",
		"base_url":    "[REDACTED]",
		"note_url":    "",
		"name":        "https://kept.example.com/path",
	}
	for k, v := range want {
		if out[k] != v {
			t.Errorf("%s = %v, want %v", k, out[k], v)
		}
	}
	if n := out["nested"].(map[string]interface{}); n["url"] != "https://hooks.example.com/[REDACTED]" {
		t.Errorf("nested url: %v", n["url"])
	}
	if in["url"] == out["url"] {
		t.Error("input must not be modified")
	}
}
