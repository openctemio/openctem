package handler

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/integration"
)

// The signing secret is write-only: an integration read returns none of its
// stored values, encrypted or not.
func TestSanitizeConfigMap_RedactsSigningSecret(t *testing.T) {
	meta := map[string]any{
		integration.MetaSigningSecret:              "ciphertext-current",
		integration.MetaSigningSecretPrevious:      "ciphertext-previous",
		integration.MetaSigningSecretPreviousUntil: "2026-10-23T00:00:00Z",
		integration.MetaSigningSecretRotatedAt:     "2026-10-22T00:00:00Z",
		"channel_name":                             "ops",
	}
	out := sanitizeConfigMap(meta)
	for _, k := range []string{integration.MetaSigningSecret, integration.MetaSigningSecretPrevious} {
		if out[k] != "[REDACTED]" {
			t.Fatalf("%s = %v, want redacted", k, out[k])
		}
	}
	if out["channel_name"] != "ops" {
		t.Fatalf("non-secret key changed: %v", out["channel_name"])
	}
}
