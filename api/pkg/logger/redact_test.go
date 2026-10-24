package logger

import (
	"log/slog"
	"testing"
)

// Sensitive keys are still masked, whole or inside a longer key; a short
// sensitive key ("iv", "pwd", "dob", "jwt") only as a whole segment, so
// ordinary fields that merely contain those letters stay readable.
func TestSanitizeAttr_ShortKeysMatchWholeSegmentsOnly(t *testing.T) {
	masked := []string{
		"password", "db_password", "jwt_secret", "api_key", "Authorization", "github_token",
		"iv", "aes_iv", "user.dob", "x-jwt", "pwd", "client_secret", "email", "ip_address",
	}
	for _, k := range masked {
		if got := sanitizeAttr(nil, slog.String(k, "value")); got.Value.String() != "[REDACTED]" {
			t.Errorf("%q not masked: %v", k, got.Value)
		}
	}
	kept := []string{"diverged", "active", "archived", "live", "derived", "receiver", "individual", "tenant_id", "status"}
	for _, k := range kept {
		if got := sanitizeAttr(nil, slog.Int(k, 3)); got.Value.Kind() != slog.KindInt64 || got.Value.Int64() != 3 {
			t.Errorf("%q was masked: %v", k, got.Value)
		}
	}
}
