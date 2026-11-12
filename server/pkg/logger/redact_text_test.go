package logger

import (
	"strings"
	"testing"
)

func TestRedactText(t *testing.T) {
	hex := "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
	secrets := map[string]string{
		"postgres dsn":  "dial failed: postgres://app:S3cr3tP@ss@db.internal:5432/openctem?sslmode=disable",
		"auth bearer":   "upstream 401: Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
		"bare bearer":   "sent Bearer abcdef1234567890 to host",
		"token kv":      "request failed token=abc123def456ghi789",
		"json password": `body {"password":"hunter2hunter2"} rejected`,
		"api key colon": "bad api_key: sk_live_0123456789",
		"basic":         "Authorization: Basic dXNlcjpwYXNzd29yZA==",
		"client secret": "client_secret='top secret value'",
		"hex 40":        "commit " + hex + " not found",
		"base64 run":    "key QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5 bad",
	}
	leaks := map[string]string{
		"postgres dsn": "S3cr3tP", "auth bearer": "eyJhbGci", "bare bearer": "abcdef1234567890",
		"token kv": "abc123def456", "json password": "hunter2", "api key colon": "sk_live",
		"basic": "dXNlcjpw", "client secret": "top secret", "hex 40": hex, "base64 run": "QUJDREVGR0hJ",
	}
	for name, in := range secrets {
		out := RedactText(in)
		if strings.Contains(out, leaks[name]) {
			t.Errorf("%s leaked: %q", name, out)
		}
		if !strings.Contains(out, redacted) {
			t.Errorf("%s not marked: %q", name, out)
		}
	}
	if got := RedactText("dial failed: postgres://app:pw@db.internal:5432/x"); !strings.Contains(got, "postgres://[REDACTED]@db.internal:5432/x") {
		t.Errorf("host lost: %q", got)
	}

	keep := []string{
		"name is required",
		"password must be at least 12 characters",
		"email already exists in this tenant",
		"basic configuration is invalid",
		"scan 3 of 10 failed: timeout after 30s",
	}
	for _, in := range keep {
		if got := RedactText(in); got != in {
			t.Errorf("plain message changed: %q -> %q", in, got)
		}
	}
}

func TestRedactedText_StripsLineBreaks(t *testing.T) {
	got := RedactedText("a\nforged token=abc123\r\nline")
	if strings.ContainsAny(got, "\r\n") || strings.Contains(got, "abc123") {
		t.Errorf("got %q", got)
	}
}
