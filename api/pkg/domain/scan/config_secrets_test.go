package scan

import (
	"encoding/json"
	"strings"
	"testing"
)

func paths(ws []ConfigSecretWarning) string {
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		out = append(out, w.Path+"="+string(w.Reason))
	}
	return strings.Join(out, ",")
}

func TestDetectConfigSecrets_Flags(t *testing.T) {
	cfg := map[string]any{
		"password":      "hunter2",
		"api_key":       "abc",
		"Client-Secret": "x",
		"headers": map[string]any{
			"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
			"X-Trace":       "plain",
		},
		"args":     []any{"-H", "Cookie: session=1", "-u", "https://user:pw@example.com/"},
		"blob":     "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MEFCQ0RFRg",
		"gh":       "ghp_" + strings.Repeat("A1b2", 9),
		"aws_id":   "AKIAABCDEFGHIJKLMNOP",
		"severity": "high",
	}
	got := paths(DetectConfigSecrets(cfg))
	want := []string{
		"Client-Secret=key_name",
		"api_key=key_name",
		"args[3]=known_format",
		"aws_id=known_format",
		"blob=high_entropy",
		"gh=known_format",
		"headers.Authorization=known_format",
		"password=key_name",
	}
	if got != strings.Join(want, ",") {
		t.Fatalf("got  %s\nwant %s", got, strings.Join(want, ","))
	}
}

func TestDetectConfigSecrets_IgnoresOrdinaryConfig(t *testing.T) {
	cfg := map[string]any{
		"custom_template_ids": []any{"3fa85f64-5717-4562-b3fc-2c963f66afa6"},
		"severity":            []any{"critical", "high"},
		"rate_limit":          150.0,
		"ports":               "1-1024",
		"templates":           "/opt/nuclei-templates/http/cves",
		"image":               "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"max_tokens":          "4096",
		"auth_type":           "bearer",
		"token_file":          "/run/secrets/token",
		"password":            "${SCAN_PASSWORD}",
		"api_key":             "env:NUCLEI_API_KEY",
		"verbose":             "true",
		"url":                 "https://example.com/a/b/c?x=1",
		"note":                "scan the staging network every night please",
		"author":              "alice",
		"design":              "fast",
	}
	if ws := DetectConfigSecrets(cfg); len(ws) != 0 {
		t.Fatalf("false positives: %s", paths(ws))
	}
}

func TestDetectConfigSecrets_NeverEchoesValues(t *testing.T) {
	secret := "SuperSecretValue-123456789"
	ws := DetectConfigSecrets(map[string]any{"token": secret})
	raw, _ := json.Marshal(ws)
	if strings.Contains(string(raw), secret) {
		t.Fatal("a warning must never carry the value")
	}
	if len(ws) != 1 {
		t.Fatalf("want 1 warning, got %d", len(ws))
	}
}

func TestDetectConfigSecrets_BoundedAndNilSafe(t *testing.T) {
	if DetectConfigSecrets(nil) != nil {
		t.Fatal("nil config: no warnings")
	}
	cfg := map[string]any{}
	for i := range 50 {
		cfg["password"+strings.Repeat("x", i)] = "v"
	}
	if n := len(DetectConfigSecrets(cfg)); n != maxSecretWarnings {
		t.Fatalf("warnings = %d, want the cap %d", n, maxSecretWarnings)
	}
	// Deep nesting stops at the depth limit instead of recursing forever.
	var deep any = map[string]any{"password": "x"}
	for range 50 {
		deep = map[string]any{"n": deep}
	}
	_ = DetectConfigSecrets(map[string]any{"root": deep})
}
